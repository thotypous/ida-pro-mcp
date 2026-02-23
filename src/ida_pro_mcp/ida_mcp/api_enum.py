import idc

from .rpc import tool
from .sync import idasync, IDAError
from .utils import (
    parse_address,
    EnumLiteralOp,
)


# ============================================================================
# Enum Literal Operations
# ============================================================================


@tool
@idasync
def apply_enum_literals(items: list[EnumLiteralOp] | EnumLiteralOp) -> list[dict]:
    """Apply enum member names to immediate operands at specific instruction addresses.

    Replaces numeric immediates with their enum representation in the disassembly
    and decompiler views. Each item specifies an instruction address, the operand
    index, and the enum to apply.

    WORKFLOW: Use `disasm` first to inspect the function and identify instruction
    addresses (EAs) and operand indices, then call this tool with those EAs.

    Capabilities:
    - Direct literals: `or reg, 0x20` -> `or reg, DP_CAPS0_V34_CAP`
    - Bitmask combinations: `or reg, 0xA0` -> `or reg, BIT5|BIT7`
      (IDA decomposes automatically for bitfield enums)
    - Inverted masks: `and reg, 0xF7` -> `and reg, ~DP_CAPS0_V90_V92_CAP`
      (set `invert: true`)

    Known limitation: literals reconstructed as multiplication by the decompiler
    (e.g. `8 * x` from `shl x, 3`) cannot be converted in headless mode.
    """
    if isinstance(items, dict):
        items = [items]

    results = []
    for item in items:
        addr_str = item.get("addr", "")
        enum_name = item.get("enum", "")
        opn = item.get("op", 1)
        invert = item.get("invert", False)

        try:
            ea = parse_address(addr_str)
            enum_id = idc.get_enum(enum_name)
            if enum_id == idc.BADADDR:
                results.append({
                    "addr": addr_str,
                    "error": f"Enum not found: {enum_name}",
                })
                continue

            # Verify operand is an immediate
            op_type = idc.get_operand_type(ea, opn)
            if op_type != idc.o_imm:
                results.append({
                    "addr": addr_str,
                    "op": opn,
                    "error": f"Operand {opn} is not an immediate (type={op_type})",
                })
                continue

            imm = idc.get_operand_value(ea, opn) & 0xFFFFFFFF
            ok = idc.op_enum(ea, opn, enum_id, 0)
            if ok and invert:
                idc.toggle_bnot(ea, opn)

            line = idc.generate_disasm_line(ea, 0)
            results.append({
                "addr": addr_str,
                "op": opn,
                "imm": hex(imm),
                "ok": bool(ok),
                "invert": invert,
                "disasm": line,
            })

        except Exception as e:
            results.append({"addr": addr_str, "error": str(e)})

    return results
