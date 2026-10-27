# injspoof -- Makefile
#
# Quick start
#   make                 portable build (AF_PACKET only)
#   make FASTPATH=1      XDP/AF_XDP fastpath (statically links libbpf/libxdp)
#   make DEBUG=1         -O0 -g, warnings non-fatal
#   make install         install to $(PREFIX)/bin   (PREFIX defaults to /usr/local)
#   make clean           remove build artefacts
#   make help            show all targets / options
#
# Objects are built out-of-tree under $(BUILD_DIR); the source tree stays clean.
# Common overrides: CC, CFLAGS, PREFIX, DESTDIR, BIN, VERSION, STATIC_BPF.

# ---- Toolchain ----------------------------------------------------------
CC         ?= gcc
CLANG      ?= clang
PKG_CONFIG ?= pkg-config
INSTALL    ?= install
RM         := rm -f
MKDIR_P    := mkdir -p

# ---- Layout -------------------------------------------------------------
SRC_DIR    := src
VEND_DIR   := vendor/cJSON
BPF_DIR    := $(SRC_DIR)/bpf
BUILD_DIR  := build
BIN        ?= injspoof
PREFIX     ?= /usr/local
BINDIR     ?= $(PREFIX)/bin

VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# ---- Flags (GNU conventions: CPPFLAGS / CFLAGS / LDFLAGS / LDLIBS) -------
CPPFLAGS   += -D_GNU_SOURCE -DINJSPOOF_BUILD_VERSION=\"$(VERSION)\" -MMD -MP
CFLAGS     ?= -O3 -march=x86-64-v2 -mtune=native -flto -pipe
CFLAGS     += -std=c11 -Wall -Wextra -Werror \
              -fno-plt -fno-semantic-interposition -fstack-protector-strong
LDFLAGS    += -flto -pthread
LDLIBS     += -lpthread

# Debug build: unoptimised, with symbols, warnings non-fatal.
ifdef DEBUG
  CFLAGS   := -O0 -g -std=c11 -Wall -Wextra -fstack-protector-strong
  CPPFLAGS += -DDEBUG
  LDFLAGS  := -pthread
endif

# ---- Sources / objects --------------------------------------------------
SRCS := \
  $(SRC_DIR)/main.c       $(SRC_DIR)/logger.c     $(SRC_DIR)/metrics.c   \
  $(SRC_DIR)/config.c     $(SRC_DIR)/packet.c     $(SRC_DIR)/raw_socket.c\
  $(SRC_DIR)/pool.c       $(SRC_DIR)/rcu.c        $(SRC_DIR)/api.c       \
  $(SRC_DIR)/fastpath.c   $(SRC_DIR)/client.c     $(SRC_DIR)/server.c    \
  $(VEND_DIR)/cJSON.c

OBJS := $(SRCS:%.c=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

# Vendored cJSON triggers -Wunused-parameter; silence it there only.
$(BUILD_DIR)/$(VEND_DIR)/cJSON.o: EXTRA_CFLAGS := -Wno-unused-parameter

# ---- Fastpath (XDP/AF_XDP) ----------------------------------------------
ifdef FASTPATH
  LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf 2>/dev/null)
  LIBXDP_CFLAGS := $(shell $(PKG_CONFIG) --cflags libxdp 2>/dev/null)
  # Detect libbpf+libxdp via pkg-config, falling back to a header probe
  # (\043 is octal '#', kept out of the makefile to avoid comment parsing).
  HAVE_BPF_DEPS := $(shell { $(PKG_CONFIG) --exists libbpf libxdp 2>/dev/null || \
      printf '\043include <bpf/libbpf.h>\n\043include <xdp/xsk.h>\n' | \
        $(CC) $(LIBBPF_CFLAGS) $(LIBXDP_CFLAGS) -E -x c - >/dev/null 2>&1 ; } \
      && echo yes || echo no)
  ifneq ($(HAVE_BPF_DEPS),yes)
    $(error FASTPATH=1 needs libbpf-dev + libxdp-dev (+ libelf-dev zlib1g-dev). \
            Run 'make fastpath-deps', or build the portable target with plain 'make'.)
  endif
  ifneq ($(shell command -v $(CLANG) >/dev/null 2>&1 && echo yes),yes)
    $(error FASTPATH=1 needs '$(CLANG)' to compile the XDP program. \
            Install clang/llvm (e.g. 'make fastpath-deps').)
  endif
  CPPFLAGS += -DBUILD_FASTPATH=1 $(LIBBPF_CFLAGS) $(LIBXDP_CFLAGS)

  # Statically link libxdp/libbpf (+elf/z[/zstd]) by default so the binary has
  # no runtime libbpf.so.1 / libxdp.so.1 dependency. STATIC_BPF=0 -> dynamic.
  STATIC_BPF ?= 1
  ifeq ($(STATIC_BPF),1)
    ZSTD_A := $(firstword $(wildcard /usr/lib/*/libzstd.a /usr/lib/libzstd.a /usr/lib64/libzstd.a))
    LDLIBS += -Wl,-Bstatic -lxdp -lbpf -lelf -lz $(if $(ZSTD_A),-lzstd) -Wl,-Bdynamic
  else
    LDLIBS += -lxdp -lbpf -lelf -lz
  endif

  BPF_OBJ := $(BUILD_DIR)/injspoof.bpf.o
  BPF_EMB := $(BUILD_DIR)/injspoof.bpf.embed.o
  OBJS    += $(BPF_EMB)
endif

# ---- Rules --------------------------------------------------------------
.DEFAULT_GOAL := all
.PHONY: all clean distclean debug fastpath fastpath-deps install uninstall dashboard help
.DELETE_ON_ERROR:

all: $(BIN)

$(BIN): $(OBJS)
	@if [ -d "$@" ]; then \
	  echo "error: '$@' exists as a DIRECTORY; remove it with 'rm -rf $@' then re-run make"; \
	  exit 1; fi
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)
	@echo "built $@ ($(VERSION))"

# Compile any source into the mirrored build tree (auto-creates subdirs).
$(BUILD_DIR)/%.o: %.c
	@$(MKDIR_P) $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) -c -o $@ $<

# XDP program: clang -> BPF bytecode.
$(BPF_OBJ): $(BPF_DIR)/injspoof.bpf.c
	@$(MKDIR_P) $(dir $@)
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_x86 \
	    -I/usr/include/$(shell uname -m)-linux-gnu -I/usr/include \
	    -c $< -o $@

# Embed the BPF object as a linkable blob exporting _binary_injspoof_bpf_o_*.
$(BPF_EMB): $(BPF_OBJ)
	cd $(BUILD_DIR) && ld -r -b binary -o $(notdir $@) $(notdir $<)
	objcopy --rename-section .data=.rodata,alloc,load,readonly,data,contents $@ $@

-include $(DEPS)

debug:
	$(MAKE) DEBUG=1

fastpath:
	$(MAKE) FASTPATH=1

fastpath-deps:
	@if [ -f /etc/debian_version ]; then \
	  sudo apt-get update && sudo apt-get install -y clang llvm libbpf-dev libxdp-dev \
	    libelf-dev pkg-config zlib1g-dev libzstd-dev ; \
	elif [ -f /etc/redhat-release ]; then \
	  sudo dnf install -y clang llvm libbpf-devel libxdp-devel elfutils-libelf-devel \
	    pkgconf zlib-devel libzstd-devel ; \
	elif [ -f /etc/arch-release ]; then \
	  sudo pacman -S --needed clang llvm libbpf libxdp libelf pkgconf zstd ; \
	else \
	  echo "Install: clang llvm libbpf-dev libxdp-dev libelf-dev pkg-config zlib zstd"; exit 1; \
	fi

install: $(BIN)
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)
	@echo "installed $(DESTDIR)$(BINDIR)/$(BIN)"
	@echo "for non-root operation, grant capabilities:"
	@echo "  AF_PACKET: sudo setcap cap_net_raw+ep $(DESTDIR)$(BINDIR)/$(BIN)"
	@echo "  FASTPATH:  sudo setcap cap_net_raw,cap_bpf,cap_net_admin+ep $(DESTDIR)$(BINDIR)/$(BIN)"

uninstall:
	$(RM) $(DESTDIR)$(BINDIR)/$(BIN)

dashboard:
	$(MAKE) -C dashboard

clean:
	-$(RM) -r $(BUILD_DIR)
	-$(RM) $(BIN)
	-@$(MAKE) -C dashboard clean 2>/dev/null || true

distclean: clean

help:
	@echo "injspoof build targets:"
	@echo "  make                          portable build (AF_PACKET only)"
	@echo "  make FASTPATH=1               XDP/AF_XDP fastpath, static libbpf/libxdp"
	@echo "  make FASTPATH=1 STATIC_BPF=0  fastpath, dynamic libbpf/libxdp"
	@echo "  make DEBUG=1                  -O0 -g, warnings non-fatal"
	@echo "  make install [PREFIX=...] [DESTDIR=...]"
	@echo "  make uninstall | clean | distclean | dashboard | fastpath-deps"
	@echo "  overrides: CC, CFLAGS, LDFLAGS, BIN, VERSION, PREFIX"
