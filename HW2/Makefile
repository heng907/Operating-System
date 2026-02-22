# ===============================
#  sched_demo Makefile (RISC-V)
# ===============================

.PHONY: all clean distclean install pack run help

# ---- Basic Configuration (adjust for your environment) ----
STUID      := 111550129
TARGET     := sched_demo_$(STUID)

# Source files
SRC        := sched_demo_$(STUID).c
OBJ        := $(SRC:.c=.o)
DEP        := $(SRC:.c=.d)

# RISC-V Cross Compiler Toolchain
CC         := riscv64-linux-gnu-gcc
CFLAGS     := -O2 -static -pthread -Wall -Wextra -Wpedantic -MMD -MP
LDFLAGS    := -static -pthread

# Paths
INITRAMFS_DIR := /home/ubuntu/initramfs
KERNEL_IMG    := /home/ubuntu/linux/arch/riscv/boot/Image
INITRAMFS_IMG := /home/ubuntu/initramfs.cpio.gz

# ---- Targets ----
all: $(TARGET)

# Include dependency files (.d)
-include $(DEP)

# Object file rule (compile .c -> .o and generate .d)
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Linking
$(TARGET): $(OBJ)
	$(CC) $(OBJ) $(LDFLAGS) -o $@

# Clean build artifacts
clean:
	@rm -f $(TARGET) $(OBJ) $(DEP)

help:
	@echo "make           -> build $(TARGET) (RISC-V static)"
	@echo "make clean     -> remove object and dependency files"
