/**
 * 人员下拉（el-select filterable）选项的 label。
 *
 * 为什么必须显式传 label —— 看 Element Plus 源码（select/option）：
 *
 *     const currentLabel = computed(() => props.label ?? (isObject(props.value) ? '' : props.value))
 *     const updateOption = (query) => {
 *       states.visible = new RegExp(escapeStringRegexp(query), 'i').test(String(currentLabel.value))
 *     }
 *
 *  1. 本地过滤**只比对 label**，拿不到 label 时就退化成比对 `value`。
 *     人员下拉的 value 是数字 id —— 于是搜 "alan" 永远匹配不上，界面显示"无匹配数据"。
 *  2. 大小写它已经用 `RegExp(query, 'i')` 处理了，**不需要我们再做 toLowerCase**。
 *
 * 内容 = 用户名 + 中文名：飞书同步过来的用户名就是英文名（Alan.Xu），
 * 用户习惯按英文名搜，所以两个都放进去，中文名/英文名都能搜到。
 * （选中后输入框显示的就是这个串，例如 "Alan.Xu 许智双"，一眼能确认是谁。）
 */
export function userLabel(u) {
  if (!u) return ''
  const username = (u.username || '').trim()
  const fullName = (u.full_name || '').trim()
  // 没有中文名的人（飞书里有 270 个），建号时 full_name 存的就是英文名，
  // 会和 username 撞成 "JohnVillanueva John Villanueva" —— 归一比较后只显示一个。
  const norm = (s) => s.toLowerCase().replace(/[\s.\-_]/g, '')
  if (username && fullName && norm(username) === norm(fullName)) return fullName
  const parts = [username, fullName].filter(Boolean)
  return parts.length ? parts.join(' ') : `#${u.id}`
}

export default userLabel
