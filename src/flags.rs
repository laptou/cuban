use bitflags::bitflags;
use num_derive::{FromPrimitive, ToPrimitive};

// Section Characteristics
bitflags! {
  #[derive(Debug, Clone, Copy)]
  pub struct SectionCharacteristics: u32 {
      const TYPE_NO_PAD = 0x0000_0008;
      const CNT_CODE = 0x0000_0020;
      const CNT_INITIALIZED_DATA = 0x0000_0040;
      const CNT_UNINITIALIZED_DATA = 0x0000_0080;
      const LNK_OTHER = 0x0000_0100;
      const LNK_INFO = 0x0000_0200;
      const LNK_REMOVE = 0x0000_0800;
      const LNK_COMDAT = 0x0000_1000;
      const GPREL = 0x0000_8000;
      const MEM_PURGEABLE = 0x0002_0000;
      const MEM_16BIT = 0x0002_0000;
      const MEM_LOCKED = 0x0004_0000;
      const MEM_PRELOAD = 0x0008_0000;
      const ALIGN_1BYTES = 0x0010_0000;
      const ALIGN_2BYTES = 0x0020_0000;
      const ALIGN_4BYTES = 0x0030_0000;
      const ALIGN_8BYTES = 0x0040_0000;
      const ALIGN_16BYTES = 0x0050_0000;
      const ALIGN_32BYTES = 0x0060_0000;
      const ALIGN_64BYTES = 0x0070_0000;
      const ALIGN_128BYTES = 0x0080_0000;
      const ALIGN_256BYTES = 0x0090_0000;
      const ALIGN_512BYTES = 0x00A0_0000;
      const ALIGN_1024BYTES = 0x00B0_0000;
      const ALIGN_2048BYTES = 0x00C0_0000;
      const ALIGN_4096BYTES = 0x00D0_0000;
      const ALIGN_8192BYTES = 0x00E0_0000;
      const LNK_NRELOC_OVFL = 0x0100_0000;
      const MEM_DISCARDABLE = 0x0200_0000;
      const MEM_NOT_CACHED = 0x0400_0000;
      const MEM_NOT_PAGED = 0x0800_0000;
      const MEM_SHARED = 0x1000_0000;
      const MEM_EXECUTE = 0x2000_0000;
      const MEM_READ = 0x4000_0000;
      const MEM_WRITE = 0x8000_0000;
  }
}

// File Characteristics
bitflags! {
  #[derive(Debug, Clone, Copy)]
  pub struct FileCharacteristics: u16 {
      const RELOCS_STRIPPED = 0x0001;
      const EXECUTABLE_IMAGE = 0x0002;
      const LINE_NUMS_STRIPPED = 0x0004;
      const LOCAL_SYMS_STRIPPED = 0x0008;
      const AGGRESSIVE_WS_TRIM = 0x0010;
      const LARGE_ADDRESS_AWARE = 0x0020;
      const BYTES_REVERSED_LO = 0x0080;
      const MACHINE_32BIT = 0x0100;
      const DEBUG_STRIPPED = 0x0200;
      const REMOVABLE_RUN_FROM_SWAP = 0x0400;
      const NET_RUN_FROM_SWAP = 0x0800;
      const SYSTEM = 0x1000;
      const DLL = 0x2000;
      const UP_SYSTEM_ONLY = 0x4000;
      const BYTES_REVERSED_HI = 0x8000;
  }
}

// DLL Characteristics
bitflags! {
  #[derive(Debug, Clone, Copy)]
  pub struct DllCharacteristics: u16 {
      const HIGH_ENTROPY_VA = 0x0020;
      const DYNAMIC_BASE = 0x0040;
      const FORCE_INTEGRITY = 0x0080;
      const NX_COMPAT = 0x0100;
      const NO_ISOLATION = 0x0200;
      const NO_SEH = 0x0400;
      const NO_BIND = 0x0800;
      const APPCONTAINER = 0x1000;
      const WDM_DRIVER = 0x2000;
      const GUARD_CF = 0x4000;
      const TERMINAL_SERVER_AWARE = 0x8000;
  }
}

// Extended DLL Characteristics
bitflags! {
  #[derive(Debug, Clone, Copy)]
  pub struct ExtendedDllCharacteristics: u16 {
      const CET_COMPAT = 0x0001;
      const FORWARD_CFI_COMPAT = 0x0040;
  }
}

#[derive(Debug, Clone, Copy, FromPrimitive, ToPrimitive)]
#[repr(u16)]
pub enum Subsystem {
    Unknown = 0,
    Native = 1,
    WindowsGui = 2,
    WindowsCui = 3,
    Os2Cui = 5,
    PosixCui = 7,
    NativeWindows = 8,
    WindowsCeGui = 9,
    EfiApplication = 10,
    EfiBootServiceDriver = 11,
    EfiRuntimeDriver = 12,
    EfiRom = 13,
    Xbox = 14,
    WindowsBootApplication = 16,
}

#[derive(Debug, Clone, Copy, FromPrimitive, ToPrimitive)]
#[repr(u16)]
pub enum DebugType {
    Unknown = 0,
    Coff = 1,
    CodeView = 2,
    Fpo = 3,
    Misc = 4,
    Exception = 5,
    Fixup = 6,
    OmapToSrc = 7,
    OmapFromSrc = 8,
    Borland = 9,
    Reserved10 = 10,
    Clsid = 11,
    VcFeature = 12,
    Pogo = 13,
    Iltcg = 14,
    Mpx = 15,
    Repro = 16,
    ExDllCharacteristics = 20,
}

#[derive(Debug, Clone, Copy, FromPrimitive, ToPrimitive)]
#[repr(u16)]
pub enum ComDatSelectType {
    NoDuplicates = 1,
    Any = 2,
    SameSize = 3,
    ExactMatch = 4,
    Associative = 5,
    Largest = 6,
    Newest = 7,
}

#[derive(Debug, Clone, Copy, FromPrimitive, ToPrimitive)]
#[repr(u16)]
pub enum BaseRelocationType {
    Absolute = 0,
    High = 1,
    Low = 2,
    HighLow = 3,
    HighAdj = 4,
    // MipsJmpAddr = 5,
    // Arm64BranchImm = 5,
    // RiscvHigh20 = 5,
    // Reserved = 6,
    // Thumb32Jmp = 7,
    // RiscvLow12I = 7,
    // RiscvLow12S = 8,
    // LoongArch32MarkLa = 8,
    // LoongArch64MarkLa = 8,
    // MipsJmpAddr16 = 9,
    Dir64 = 10,
}
