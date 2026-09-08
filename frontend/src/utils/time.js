/**
 * 统一时间显示工具。
 *
 * 本项目后端所有时间字段在数据库中以 naive UTC 存储（nc.utcnow）。
 * 序列化层面已统一补 UTC 偏移（+00:00/Z），但历史数据 / 某些直传字段
 * 仍可能是无时区后缀的裸 UTC 串（如 2026-09-08T07:57:00）。
 *
 * 为让页面显示的「提交时间 / 创建时间」与浏览器所在时区一致（国内为
 * 东八区，应比 UTC +8 小时），这里统一把后端时间当作 UTC 解析，再按
 * 浏览器本地时区渲染。避免此前把 UTC 数字误当成本地时间而少 8 小时。
 */

// 若字符串不带时区标识(Z / +hh:mm / -hh:mm)，视为裸 UTC，补 Z 再解析。
function asUtcDate(d) {
  if (d == null || d === '') return null;
  if (d instanceof Date) return d;
  const s = String(d);
  const hasTz = /(Z|[+-]\d{2}:?\d{2})$/.test(s);
  const dt = new Date(hasTz ? s : `${s}Z`);
  return isNaN(dt.getTime()) ? null : dt;
}

const pad = (n) => String(n).padStart(2, '0');

/** 展示为本地时区日期时间：YYYY-MM-DD HH:MM */
export function fmtDateTime(d) {
  const dt = asUtcDate(d);
  if (!dt) return d ? String(d).replace('T', ' ').slice(0, 16) : '';
  return `${dt.getFullYear()}-${pad(dt.getMonth() + 1)}-${pad(dt.getDate())} ${pad(dt.getHours())}:${pad(dt.getMinutes())}`;
}

/** 展示为本地时区日期时间（含秒）：YYYY-MM-DD HH:MM:SS */
export function fmtDateTimeFull(d) {
  const dt = asUtcDate(d);
  if (!dt) return d ? String(d).replace('T', ' ').slice(0, 19) : '';
  return `${dt.getFullYear()}-${pad(dt.getMonth() + 1)}-${pad(dt.getDate())} ${pad(dt.getHours())}:${pad(dt.getMinutes())}:${pad(dt.getSeconds())}`;
}

/** 仅本地时区日期：YYYY-MM-DD */
export function fmtDate(d) {
  const dt = asUtcDate(d);
  if (!dt) return d ? String(d).slice(0, 10) : '';
  return `${dt.getFullYear()}-${pad(dt.getMonth() + 1)}-${pad(dt.getDate())}`;
}
