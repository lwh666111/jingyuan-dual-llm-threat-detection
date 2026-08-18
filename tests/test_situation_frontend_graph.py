import json
import subprocess
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_JS = PROJECT_ROOT / "frontend_dashboard" / "public" / "app.js"


class SituationFrontendGraphTests(unittest.TestCase):
    def run_node_probe(self, body: str) -> dict:
        script = f"""
const fs = require("fs");
const source = fs.readFileSync({json.dumps(str(APP_JS))}, "utf8");
const match = source.match(/function aggregateSituationNodes[\\s\\S]*?(?=\\nfunction buildSituationGraphView)/);
if (!match) throw new Error("aggregateSituationNodes was not found");
eval(match[0]);
{body}
"""
        completed = subprocess.run(
            ["node", "-e", script],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        return json.loads(completed.stdout)

    def test_dense_chain_never_merges_different_swimlanes(self):
        result = self.run_node_probe(
            """
const stages = ["recon", "credential", "exploit", "execution", "impact"];
const nodes = Array.from({ length: 30 }, (_, index) => {
  const stage = stages[index % stages.length];
  return {
    id: `node-${index}`,
    stage,
    action_type: `${stage}-${index % 3}`,
    name: `${stage} action ${index % 3}`,
    count: index + 1,
    confidence: 0.8,
    occurred_at: new Date(Date.UTC(2026, 7, 11, 3, index)).toISOString(),
  };
});
const compacted = aggregateSituationNodes(nodes, 10);
console.log(JSON.stringify({
  count: compacted.length,
  stages: [...new Set(compacted.map((item) => item.stage))],
  hasCrossStageGroup: compacted.some((item) =>
    new Set(item.members.map((member) => member.stage)).size > 1
  ),
}));
"""
        )
        self.assertLessEqual(result["count"], 10)
        self.assertEqual(
            set(result["stages"]),
            {"recon", "credential", "exploit", "execution", "impact"},
        )
        self.assertFalse(result["hasCrossStageGroup"])

    def test_dashboard_time_is_pinned_to_beijing(self):
        source = APP_JS.read_text(encoding="utf-8")
        self.assertIn('timeZone: "Asia/Shanghai"', source)

    def test_ai_report_queue_has_live_position_and_priority_action(self):
        source = APP_JS.read_text(encoding="utf-8")
        self.assertIn("前方还有 ${ahead} 个任务", source)
        self.assertIn("data-prioritize-ai-report", source)
        self.assertIn("/prioritize-report", source)
        self.assertIn("beginSituationAiQueuePolling", source)
        self.assertLess(
            source.index('const processing = status === "processing";'),
            source.index("const queueProgress = processing ?"),
        )

    def test_legacy_ai_report_utc_time_is_rendered_as_beijing(self):
        script = f"""
const fs = require("fs");
const source = fs.readFileSync({json.dumps(str(APP_JS))}, "utf8");
const match = source.match(/function normalizeSituationReportTime[\\s\\S]*?(?=\\nfunction renderSituationReportSection)/);
if (!match) throw new Error("normalizeSituationReportTime was not found");
eval(match[0]);
console.log(JSON.stringify({{
  legacy: normalizeSituationReportTime("窗口 2026-08-11 04:15:19 至 2026-08-11T04:32:31Z", {{}}),
  tagged: normalizeSituationReportTime("窗口 2026-08-11 12:15:19", {{ time_zone: "Asia/Shanghai" }}),
}}));
"""
        completed = subprocess.run(
            ["node", "-e", script],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        result = json.loads(completed.stdout)
        self.assertEqual(
            result["legacy"],
            "窗口 2026-08-11 12:15:19 至 2026-08-11 12:32:31",
        )
        self.assertEqual(result["tagged"], "窗口 2026-08-11 12:15:19")


if __name__ == "__main__":
    unittest.main()
