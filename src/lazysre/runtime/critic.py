from lazysre.models import CriticResult, StepResult


class Critic:
    def evaluate(self, objective: str, plan: list[str], steps: list[StepResult]) -> CriticResult:
        if not steps:
            return CriticResult(done=False, score=0.0, feedback="还没有执行任何步骤。")

        success_count = sum(1 for s in steps if s.success)
        coverage = success_count / max(len(plan), 1)
        score = min(1.0, coverage)
        done = success_count >= len(plan) and len(plan) > 0
        feedback = "执行完成，可以输出总结。" if done else "执行不充分，建议补充关键诊断步骤。"

        # 若目标关键词完全未出现在执行结果中，降低分数。
        objective_keywords = {w for w in objective.split() if len(w) > 1}
        if objective_keywords:
            text = " ".join(s.output for s in steps).lower()
            hit = any(k.lower() in text for k in objective_keywords)
            if not hit:
                score = max(0.1, score - 0.2)

        return CriticResult(done=done, score=round(score, 3), feedback=feedback)

