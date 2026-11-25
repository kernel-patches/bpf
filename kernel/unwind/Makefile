ifdef CONFIG_FUNCTION_TRACER
CFLAGS_REMOVE_dwarf_cfi.o = $(CC_FLAGS_FTRACE)
endif
KASAN_SANITIZE_dwarf_cfi.o := n
KCSAN_SANITIZE_dwarf_cfi.o := n
UBSAN_SANITIZE_dwarf_cfi.o := n
KMSAN_SANITIZE_dwarf_cfi.o := n
KCOV_INSTRUMENT_dwarf_cfi.o := n

obj-$(CONFIG_UNWIND_DWARF_CFI)		+= dwarf_cfi.o
obj-$(CONFIG_UNWIND_USER)		+= user.o deferred.o
obj-$(CONFIG_UNWIND_DWARF_CFI_KUNIT_TEST) += dwarf_cfi_kunit.o
