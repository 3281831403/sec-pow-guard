接口加了工作量证明，脚本把难度字段改成零，仍然一路请求成功：难度换算按左移位数直接左移，难度为零时目标为零；难度不设上限，超大难度导致目标为零永远无解；校验只比较计数器是否非负，不看结果与目标关系；挑战难度取自请求，客户端可自行降低难度；挑战不绑定客户端，可被转发使用；消费挑战不删除，可重复提交同一解；消费挑战不校验过期，过期解仍可用；求解返回第一个满足解的计数器但校验用另一套目标值，两者不一致；策略校验不检查难度上限；批量校验复用挑战状态，第二个请求命中第一个请求的挑战。pow/guard.py 是核心，tests/test_guard.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

## 运行方式

在仓库根目录执行：

python -m pytest tests -q

初始基线必须恰好为 15 failed，0 error，且 15 个失败全部由 src/pow/guard.py 的桩抛出 NotImplementedError 导致。修复目标是按题面顺序修掉 10 个缺陷，使 15 个测试全部通过。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属方向 | 安全 |
| 细分领域 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言与框架 | Python 3, pytest |
| 外部依赖 | 无外部依赖 |

## 测试约束

tests 目录下的测试不可修改。15 个测试由 10 条缺陷回归和 5 条基础行为组成。修复时只允许修改 src/pow/guard.py，不得为了让测试通过而改写测试、伪造夹具或跳过用例。

## 目录布局

仓库采用 src 布局，实现包 src/pow 与测试目录 tests 分离：

sec-pow-guard/
    README.md
    pyproject.toml
    src/
        pow/
            __init__.py
            guard.py
    tests/
        conftest.py
        test_guard.py

## 接口契约

target_for：256 位目标值按 difficulty 计算为 1 左移 256 减 difficulty 位；difficulty 必须是 1 到 32 之间的整数，越界抛 ValueError。

counter_valid：把完整候选串按 UTF-8 编码后做 SHA-256，摘要按大端解释为整数，仅当该整数严格小于 target 时返回 True；target 小于等于零一律返回 False。nonce 是包含末尾计数器的完整候选串。

issue_challenge：store 是可变映射，以挑战 id 为键。client 是唯一允许使用该挑战的客户端，difficulty 是服务端选定的难度，now 与 ttl 的单位为秒。挑战包含 id、client、difficulty、issued_at、expires_at、used 字段。返回给调用方的是展示副本，store 中的记录是权威数据。

check_challenge：仅当 id 仍存在于 store、used 为 False、now 严格小于 expires_at，且展示副本的 client 与 difficulty 均与权威记录一致时返回 True。

consume_challenge：按真实时钟校验未过期，校验通过后从 store 删除记录并返回被消费的记录；未知、重复消费、已过期、client 或 difficulty 被篡改时抛 ValueError。

solve：从 0 开始递增计数器，候选串为 nonce 加冒号再加计数器，返回使 counter_valid 对 target_for(difficulty) 成立的最小计数器。

validate_policy：按固定顺序返回问题列表，标签为 max_difficulty_missing、max_difficulty_exceeds_limit、challenge_ttl_invalid、client_binding_required。合法策略返回空列表。

pow_batch：requests 的每一项是包含 client、store、challenge、nonce 的映射。批量中的每个请求独立校验，不共享挑战状态；返回 results 布尔列表、accepted 计数和 problems 列表。策略不合法时整批拒绝。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

