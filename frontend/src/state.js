const RECENT_TASKS = "lexagent.platform.tasks.v2";

function readList(storage, key) {
  try {
    const value = JSON.parse(storage?.getItem(key) || "[]");
    return Array.isArray(value) ? value : [];
  } catch { return []; }
}

export function createRecentStore(storage = globalThis.localStorage) {
  return {
    tasks() { return readList(storage, RECENT_TASKS); },
    addTask(task) {
      const items = [task, ...this.tasks().filter((item) => item.task_id !== task.task_id)].slice(0, 20);
      storage?.setItem(RECENT_TASKS, JSON.stringify(items));
      return items;
    },
    replaceTasks(items) {
      storage?.setItem(RECENT_TASKS, JSON.stringify(items.slice(0, 20)));
      return this.tasks();
    },
    clear() { storage?.removeItem(RECENT_TASKS); }
  };
}

export function asItems(value) {
  return Array.isArray(value) ? value : Array.isArray(value?.items) ? value.items : [];
}

export function lastDaysRange(days = 7, now = new Date()) {
  return { from: new Date(now.getTime() - days * 86400000).toISOString(), to: now.toISOString() };
}

export function summarizeUsage(items = []) {
  return items.reduce((summary, item) => {
    summary.total += Number(item.actual || 0);
    summary.requests += 1;
    summary.degraded += item.degraded ? 1 : 0;
    summary.providers.add(item.provider || "unknown");
    return summary;
  }, { total: 0, requests: 0, degraded: 0, providers: new Set() });
}
