"""
安全基线数据导入脚本
将5个Excel文件（含安全合规V2.2）的数据导入数据库的 baseline_category 和 baseline_item 表。
只处理5个开发安全基线类型，不影响系统内置的其他基线分类。

用法：
    cd backend
    python scripts/import_baseline.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pandas as pd
from sqlalchemy.orm import sessionmaker
from app.database import engine
from app.models import BaselineCategory, BaselineItem

BASE_DIR = os.path.expanduser(r'~/Desktop/安全基线')
if not os.path.exists(BASE_DIR):
    for c in [r'C:/Users/ningran/Desktop/安全基线']:
        if os.path.exists(c):
            BASE_DIR = c
            break

# baseline_type -> (精确文件名匹配, 检查表sheet列表)
FILES = [
    ('security_requirement', 'L4-32-安全需求基线-含安全合规',
     ['B端安全需求基线检查表', 'C端安全需求基线检查表']),
    ('app_dev', 'L4-34-APP开发安全基线-含安全合规', ['APP开发安全基线检查表']),
    ('frontend_dev', 'L4-35-前端开发安全基线-含安全合规', ['前端开发安全基线检查表']),
    ('backend_dev', 'L4-36-后端开发安全基线-含安全合规', ['后端开发安全基线检查表']),
    ('firmware_dev', 'L4-37-固件开发安全基线-含安全合规', ['固件开发安全基线检查表']),
]

TARGET_TYPES = [f[0] for f in FILES]

# 合规框架映射模块，不导入为检查项（可能嵌套在检查表中）
SKIP_MODULES = ['NIST 合规', 'HIPAA 合规', 'SOC2 合规', 'NIST合规', 'HIPAA合规', 'SOC2合规',
                'NIST', 'HIPAA', 'SOC2', 'SOC 2']


def find_file(keyword):
    """精确匹配：文件名必须完整包含 keyword（含版本后缀）。"""
    for f in os.listdir(BASE_DIR):
        if f.endswith('.xlsx') and keyword in f:
            # 排除 "L4-32-安全需求基线.xlsx" 这类不完整版本
            return os.path.join(BASE_DIR, f)
    return None


def parse_sheet(filepath, sheet_name):
    df = pd.read_excel(filepath, sheet_name=sheet_name, header=None)
    header_row = None
    for i in range(min(15, len(df))):
        vals = df.iloc[i].astype(str).tolist()
        if '序号' in vals or '控制模块' in vals:
            header_row = i
            break
    if header_row is None:
        return []

    df = pd.read_excel(filepath, sheet_name=sheet_name, header=header_row)
    df.columns = [str(c).strip() for c in df.columns]

    col_module = col_point = col_content = None
    for col in df.columns:
        if '控制模块' in col:
            col_module = col
        elif '控制点' in col:
            col_point = col
        elif '内容' in col:
            col_content = col
    if not col_module or not col_point:
        return []

    records = []
    current_module = None
    for _, row in df.iterrows():
        module = str(row.get(col_module, '')).strip()
        point = str(row.get(col_point, '')).strip()
        content = str(row.get(col_content, '')).strip() if col_content else ''
        if point == 'nan' or point == '' or point == '控制点':
            continue
        if module != 'nan' and module != '':
            current_module = module
        if not current_module:
            continue
        # 跳过合规框架映射模块
        if any(k in current_module for k in SKIP_MODULES):
            continue
        if content == 'nan':
            content = ''
        content = content.replace('\\n', '\n').strip()
        records.append({'category': current_module, 'name': point, 'description': content})
    return records


def make_code(baseline_type, module_name):
    """生成全局唯一的 code：用 baseline_type 前缀。"""
    safe = module_name.replace('/', '_').replace('\\', '_').replace(' ', '_').strip('_')
    return f"{baseline_type}_{safe}"[:60]


def main():
    db = sessionmaker(bind=engine)()

    # 只删除这5个基线类型下的旧数据（不清空系统内置）
    for t in TARGET_TYPES:
        cats = db.query(BaselineCategory).filter(BaselineCategory.baseline_type == t).all()
        for c in cats:
            db.query(BaselineItem).filter(BaselineItem.category_id == c.id).delete()
            db.delete(c)
    db.commit()

    total_cats = total_items = 0
    for baseline_type, keyword, sheets in FILES:
        filepath = find_file(keyword)
        if not filepath:
            print(f"[跳过] 未找到 {keyword}")
            continue
        print(f"\n处理: {os.path.basename(filepath)} ({baseline_type})")
        for sheet in sheets:
            records = parse_sheet(filepath, sheet)
            print(f"  sheet[{sheet}] -> {len(records)} 条")
            # 合并到该类型的模块
            modules = {}
            for r in records:
                modules.setdefault(r['category'], []).append(r)
            for module_name, items in modules.items():
                cat = db.query(BaselineCategory).filter(
                    BaselineCategory.baseline_type == baseline_type,
                    BaselineCategory.name == module_name,
                ).first()
                if not cat:
                    cat = BaselineCategory(
                        name=module_name,
                        code=make_code(baseline_type, module_name),
                        description=module_name,
                        baseline_type=baseline_type,
                        sort=0,
                    )
                    db.add(cat)
                    db.flush()
                    total_cats += 1
                for idx, it in enumerate(items):
                    existing = db.query(BaselineItem).filter(
                        BaselineItem.category_id == cat.id,
                        BaselineItem.name == it['name'],
                    ).first()
                    if existing:
                        existing.description = it['description']
                        continue
                    db.add(BaselineItem(
                        category_id=cat.id, name=it['name'],
                        description=it['description'], check_method='manual',
                        severity='medium', is_required=True, sort=idx,
                    ))
                    total_items += 1
            db.commit()

    db.close()
    with open(os.path.join(os.path.dirname(__file__), 'import_result.txt'), 'w', encoding='utf-8') as f:
        f.write(f"导入完成: {total_cats} 个分类, {total_items} 个检查项\n")


if __name__ == '__main__':
    main()
