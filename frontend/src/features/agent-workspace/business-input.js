export function parseBusinessInput(text) {
  let input;
  try { input = JSON.parse(text); }
  catch { throw new Error("请输入有效的业务 JSON 对象。"); }
  if (input === null || Array.isArray(input) || typeof input !== "object") {
    throw new Error("业务输入必须是 JSON 对象。");
  }
  return input;
}
