#!/usr/bin/env python3

import sys
import yaml
import ctypes

class Banked(ctypes.LittleEndianStructure):
    _fields_ = [
            ("spsr", ctypes.c_uint32),
            ("sp", ctypes.c_uint32),
            ("lr", ctypes.c_uint32),
            ]

class Cpu(ctypes.LittleEndianStructure):
    _fields_ = [
            ("r0", ctypes.c_uint32),
            ("r1", ctypes.c_uint32),
            ("r2", ctypes.c_uint32),
            ("r3", ctypes.c_uint32),
            ("r4", ctypes.c_uint32),
            ("r5", ctypes.c_uint32),
            ("r6", ctypes.c_uint32),
            ("r7", ctypes.c_uint32),
            ("r8", ctypes.c_uint32),
            ("r9", ctypes.c_uint32),
            ("r10", ctypes.c_uint32),
            ("r11", ctypes.c_uint32),
            ("r12", ctypes.c_uint32),
            ("sp", ctypes.c_uint32),
            ("lr", ctypes.c_uint32),
            ("pc", ctypes.c_uint32),
            ("daif", ctypes.c_uint32),
            ("scr", ctypes.c_uint32),
            ("dacr", ctypes.c_uint32),
            ("ttbr0", ctypes.c_uint32),
            ("ttbr1", ctypes.c_uint32),
            ("sctlr", ctypes.c_uint32),
            ("vbar", ctypes.c_uint32),
            ("cpsr", ctypes.c_uint32),
            ("spsr", ctypes.c_uint32),
            ("_usrsys", Banked),
            ("_svc", Banked),
            ("_abt", Banked),
            ("_und", Banked),
            ("_irq", Banked),
            ("_fiq", Banked),
            ("_hyp", Banked),
            ("_mon", Banked),
            ]

PAGE_SIZE = 0x1000
with open(sys.argv[1], 'rb') as fd:
    data = fd.read()

with open("mem", 'wb') as fd:
    fd.write(data[:-PAGE_SIZE])

_USR = 0x10
_FIQ = 0x11
_IRQ = 0x12
_SVC = 0x13
_MON = 0x16
_ABT = 0x17
_HYP = 0x1a
_UND = 0x1b
_SYS = 0x1f

with open("reg", 'wb') as fd:
    fd.write(data[-PAGE_SIZE:])

yaml.add_representer(int, lambda x,y : x.represent_int(hex(y)))
with open("reg.yaml", 'w') as fd:
    cpu = Cpu.from_buffer_copy(data[-PAGE_SIZE:])
    mode = cpu.cpsr&0x1f
    assert (mode in [_USR, _FIQ, _IRQ, _SVC, _MON, _ABT, _HYP, _UND, _SYS])
    spsr = cpu._usrsys.spsr if mode in [_USR, _SYS] else \
        cpu._fiq.spsr if mode == _FIQ else \
        cpu._irq.spsr if mode == _IRQ else \
        cpu._svc.spsr if mode == _SVC else \
        cpu._mon.spsr if mode == _MON else \
        cpu._abt.spsr if mode == _ABT else \
        cpu._hyp.spsr if mode == _HYP else \
        cpu._und.spsr if mode == _UND else \
        0
    regs = {
            "regs": [
                cpu.r0,
                cpu.r1,
                cpu.r2,
                cpu.r3,
                cpu.r4,
                cpu.r5,
                cpu.r6,
                cpu.r7,
                cpu.r8,
                cpu.r9,
                cpu.r10,
                cpu.r11,
                cpu.r12,
                cpu.sp,
                cpu.lr,
                cpu.pc,
                ],
            "daif": cpu.daif,
            "cp15.scr_el3": cpu.scr,
            "cp15.hcr_el2": 0,
            "cp15.dacr_ns": cpu.dacr,
            "cp15.dacr_s": cpu.dacr,
            "cp15.ttbr0_el": [cpu.ttbr0]*4,
            "cp15.ttbr1_el": [cpu.ttbr1]*4,
            "cp15.sctlr_el": [cpu.sctlr]*4,
            "cp15.vbar_el": [cpu.vbar]*4,
            "uncached_cpsr": cpu.cpsr,
            "spsr": cpu.spsr,
            "banked_spsr": [
                cpu._usrsys.spsr,
                cpu._svc.spsr,
                cpu._abt.spsr,
                cpu._und.spsr,
                cpu._irq.spsr,
                cpu._fiq.spsr,
                cpu._hyp.spsr,
                cpu._mon.spsr,
                ],
            "banked_r13": [
                cpu._usrsys.sp,
                cpu._svc.sp,
                cpu._abt.sp,
                cpu._und.sp,
                cpu._irq.sp,
                cpu._fiq.sp,
                cpu._hyp.sp,
                cpu._mon.sp,
                ],
            "banked_r14": [
                cpu._usrsys.lr,
                cpu._svc.lr,
                cpu._abt.lr,
                cpu._und.lr,
                cpu._irq.lr,
                cpu._fiq.lr,
                cpu._hyp.lr,
                cpu._mon.lr,
                ],
            }
    yaml.dump(regs, fd)
