# 发布与恢复手册

## 正常自动发布

1. main 的固定 SHA 运行测试与 CI 构建。
2. 读取当时的 release SHA 作为 baseline。
3. 生成 canonical manifest、candidate.zip 与独立传输 SHA-256。
4. publish job 只下载同一 run ID 和 run attempt 的制品。
5. 解包时拒绝路径穿越、重复项和符号链接，并校验完整 manifest。
6. 再次读取远端 release；与 baseline 不同就失败并要求重新验证。
7. 以 baseline 为父提交；首次发布则以已验证 main 为父提交。
8. 只做 fast-forward 推送，绝不 force push。

## 本地演练

    python scripts/build.py
    python scripts/validate.py
    python scripts/seal.py create
    python scripts/seal.py verify --archive dist/candidate.zip --digest dist/candidate.zip.sha256 --output candidate-verified
    python scripts/release.py publish --candidate candidate-verified --local-only

第二次演练应生成 release 的普通子提交：

    git log --graph --oneline release

## 推送结果未知

网络错误不能直接解释为成功或失败。发布器会重新抓取远端 release：

- 远端 commit 和 build ID 都与候选一致，才算成功；
- 不一致或无法读取时，保持失败状态并等待人工处理。

## 首次发布边界

首次只有依赖历史基线的 protected 变化门和 delta 门显示 N/A。语法、规则类型、公共后缀、CIDR、冲突、非空、类别下限、来源下限以及注入检测仍必须全部 PASS。

## 回滚

回滚使用普通后继提交，不重写历史：

    python scripts/release.py rollback TARGET_RELEASE_COMMIT --local-only

正式远端回滚去掉 local-only。执行前必须确认目标 commit 同时包含 rules、reports 和 metadata。
