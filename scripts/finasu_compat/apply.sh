#!/usr/bin/env bash
# FinaSU 内核侧 SUSFS 集成（原生形态校验）
#
# FinaSU 上游自 cdf8711a + 5b83330b（2026-10-23）起已在树内原生集成 SUSFS：
#   - kernel/extension/susfs.c（CONFIG_KSU_SUSFS 下编译）提供内核侧 50_add
#     主补丁内联调用的全部入口点：ksu_handle_execveat(_sucompat)、
#     ksu_handle_post_execveat_sucompat、ksu_setup_preinit_file、
#     ksu_preinit_handle_post_execveat（sucompat/preinit/init.rc/input 仍走
#     FinaSU 自己的 kprobe 钩子，入口点仅满足主补丁的直接调用）；
#   - setuid_hook.c 自带 CONFIG_KSU_SUSFS 三参数 ksu_handle_setresuid
#     （zygote/zygote_next 域门控）；
#   - feature/selinux_hide.c 的 my_setprocattr / my_write_context /
#     my_write_access 已按 SUSFS 内联钩子要求全局导出；
#   - susfs_init() 由驱动 init 原生调用，Kconfig 自带完整 KSU_SUSFS 菜单。
#
# 官方 docs/builtin-integration.md 明确要求**不要**对 FinaSU 整体应用
# susfs4ksu 的 10_enable_susfs_for_ksu.patch（"Do not apply the driver-side
# patch as a whole; this tree already implements many of its hunks and its
# hook model differs"）：该补丁面向上游 KernelSU 的手动钩子模型，会把
# hook/tp_marker.o 等编译单元移出 Kbuild，而 FinaSU 的 kprobe 模型仍引用
# 这些符号（setuid_hook.c / supercall/dispatch.c），驱动侧一旦打补丁就会在
# vmlinux 链接阶段报 undefined symbol。
#
# 因此本脚本不再应用任何驱动侧补丁（2026-10-24 起废弃旧的
# 「10_enable + drift-fixes + 内联适配」方案），只校验原生集成结构，
# 结构漂移时立即报错而不是静默退化；内核侧 50_add 主补丁由
# scripts/susfs_fixes/apply.sh 照常应用（其内联钩子按 KernelSU 源码内容
# 探测，见 ksu_susfs_hooks.py）。
#
# 用法: apply.sh [KSU_DIR]（默认 KernelSU）
set -eo pipefail

KSU_DIR="${1:-KernelSU}"
KERNEL_ROOT="${KERNEL_ROOT:-$PWD}"
FINASU_KSU="$KERNEL_ROOT/$KSU_DIR/kernel"

fail() {
  echo "::error::$1" >&2
  exit 1
}

echo "步骤 1/1: 校验 FinaSU 原生 SUSFS 集成..."

# 原生集成标志：extension/susfs.c（5b83330b 起存在）
if [ ! -f "$FINASU_KSU/extension/susfs.c" ]; then
  echo "::error::FinaSU 未包含原生 SUSFS 集成（缺少 $KSU_DIR/kernel/extension/susfs.c）。" >&2
  echo "::error::当前检出的 FinaSU 早于 5b83330b（2026-10-23），或上游结构再次变化。" >&2
  echo "::error::旧的 10_enable_susfs_for_ksu.patch 驱动侧补丁方案已随上游原生集成废弃，" >&2
  echo "::error::不支持该形态；请确认 get-manager 传入的 ksuCommit 指向最新 Release。" >&2
  exit 1
fi

# 1) Kconfig 自带完整 KSU_SUSFS 菜单（「添加 SUSFS 配置」步骤写入的
#    CONFIG_KSU_SUSFS* 必须全部有对应定义，否则 olddefconfig 会静默丢弃）
for OPT in KSU_SUSFS KSU_SUSFS_SUS_PATH KSU_SUSFS_SUS_MOUNT KSU_SUSFS_SUS_KSTAT \
           KSU_SUSFS_SPOOF_UNAME KSU_SUSFS_ENABLE_LOG KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS \
           KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG KSU_SUSFS_OPEN_REDIRECT KSU_SUSFS_SUS_MAP; do
  grep -q "^config $OPT\$" "$FINASU_KSU/Kconfig" \
    || fail "FinaSU Kconfig 缺少 config $OPT（上游结构可能已变化）"
done

# 2) extension/susfs.c 提供 50_add 主补丁在 fs/exec.c 内联调用的全部入口点；
#    ksu_susfs_hooks.py 靠源码探测这些符号，缺失时会静默退化（preinit /
#    sucompat 直连失效），这里提前校验
for SYM in ksu_handle_execveat ksu_handle_execveat_sucompat ksu_handle_post_execveat_sucompat \
           ksu_setup_preinit_file ksu_preinit_handle_post_execveat; do
  grep -qE "^(int|void) $SYM\(" "$FINASU_KSU/extension/susfs.c" \
    || fail "FinaSU extension/susfs.c 缺少全局入口点: $SYM"
done

# 3) setuid_hook.c 三参数 SUSFS 实现（内核侧 kernel/sys.c 的 3 参调用依赖该签名；
#    zygote 域门控由 FinaSU 原生的 susfs_is_current_zygote_domain() 提供）
grep -q '^int ksu_handle_setresuid(uid_t ruid, uid_t euid, uid_t suid)$' "$FINASU_KSU/hook/setuid_hook.c" \
  || fail "FinaSU setuid_hook.c 缺少三参数 ksu_handle_setresuid（上游结构可能已变化）"

# 4) selinux_hide.c 的 my_* 符号已全局导出（6.6/6.12 主补丁在
#    security/selinux/{hooks,selinuxfs}.c 内联调用这些符号）
for SYM in my_write_context my_write_access my_setprocattr; do
  grep -qE "^(ssize_t|int) $SYM\(" "$FINASU_KSU/feature/selinux_hide.c" \
    || fail "FinaSU selinux_hide.c 未全局导出 $SYM（SUSFS 内联 SELinux 钩子将无法链接）"
done

# 5) susfs_init() 由驱动 init 原生调用（10_enable 时代需要内联补丁注入）
grep -q 'susfs_init();' "$FINASU_KSU/core/init.c" \
  || fail "FinaSU init.c 未调用 susfs_init()（上游结构可能已变化）"

echo "FinaSU 原生 SUSFS 集成校验通过（驱动侧无需补丁；内核侧 50_add 主补丁由 scripts/susfs_fixes/apply.sh 应用）"
