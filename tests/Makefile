CXX = g++
CXXFLAGS = -std=c++20 -O3 -Wall -Wextra -fno-exceptions
CXX11FLAGS = -std=c++11 -O3 -Wall -Wextra -fno-exceptions
INCLUDES = -I..
SHELL := /bin/bash
.SHELLFLAGS := -o pipefail -c

PCLMUL_FLAGS =
AESNI_FLAGS = -mssse3 -maes $(PCLMUL_FLAGS)
VAES_FLAGS = $(AESNI_FLAGS) -mavx2 -mvaes
VAES512_FLAGS = $(VAES_FLAGS) -mavx512f -mavx512bw -mavx512dq -mavx512vl
ARM_CRYPTO_FLAGS = -march=native
SANITIZER_FLAGS = -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer

# Output directories
OUTDIR = out
BINDIR = $(OUTDIR)/bin
REPORTDIR = $(OUTDIR)/reports
TIMESTAMP := $(shell date +%Y%m%d_%H%M%S)

# Platform detection
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
NATIVE_DEFINES := $(shell echo | $(CXX) -march=native -dM -E - 2>/dev/null)

# Build each standalone implementation with only the flags that it requires.
# The unified test uses the strongest backend executable on this machine.
AES_NI_SUPPORT = no
PCLMUL_SUPPORT = no
VAES_SUPPORT = no
VAES512_SUPPORT = no
ARM_CRYPTO_SUPPORT = no
WAES_TARGET_FLAGS =
TESTS = test_generic test_waes

ifneq ($(filter x86_64 amd64,$(UNAME_M)),)
    PLATFORM = x86_64
    ifneq ($(findstring __PCLMUL__,$(NATIVE_DEFINES)),)
        PCLMUL_SUPPORT = yes
        PCLMUL_FLAGS = -mpclmul
    endif
    ifneq ($(findstring __AES__,$(NATIVE_DEFINES)),)
        ifneq ($(findstring __SSSE3__,$(NATIVE_DEFINES)),)
            AES_NI_SUPPORT = yes
            TESTS += test_aes_ni
            WAES_TARGET_FLAGS = $(AESNI_FLAGS)
        endif
    endif
    ifneq ($(findstring __AVX2__,$(NATIVE_DEFINES)),)
        ifneq ($(findstring __VAES__,$(NATIVE_DEFINES)),)
            ifeq ($(AES_NI_SUPPORT),yes)
                VAES_SUPPORT = yes
                TESTS += test_vaes
                WAES_TARGET_FLAGS = $(VAES_FLAGS)
            endif
        endif
    endif
    ifeq ($(VAES_SUPPORT),yes)
        ifneq ($(findstring __AVX512F__,$(NATIVE_DEFINES)),)
            ifneq ($(findstring __AVX512BW__,$(NATIVE_DEFINES)),)
                ifneq ($(findstring __AVX512DQ__,$(NATIVE_DEFINES)),)
                    ifneq ($(findstring __AVX512VL__,$(NATIVE_DEFINES)),)
                        VAES512_SUPPORT = yes
                        TESTS += test_vaes512
                        WAES_TARGET_FLAGS = $(VAES512_FLAGS)
                    endif
                endif
            endif
        endif
    endif
else ifneq ($(filter aarch64 arm64,$(UNAME_M)),)
    PLATFORM = arm64
    ifneq ($(strip $(findstring __ARM_FEATURE_CRYPTO,$(NATIVE_DEFINES))$(findstring __ARM_FEATURE_AES,$(NATIVE_DEFINES))),)
        ARM_CRYPTO_SUPPORT = yes
        TESTS += test_armv8
        WAES_TARGET_FLAGS = $(ARM_CRYPTO_FLAGS)
    endif
else
    PLATFORM = unknown
endif

# Full paths of test binaries (derived from TESTS list)
BINS = $(addprefix $(BINDIR)/, $(TESTS))
BUILD_CHECKS = $(BINDIR)/test_generic_multitu $(BINDIR)/test_cxx11_gcm_generic
ifeq ($(AES_NI_SUPPORT),yes)
    BUILD_CHECKS += $(BINDIR)/test_cxx11_gcm_aes_ni
endif
ifeq ($(VAES_SUPPORT),yes)
    BUILD_CHECKS += $(BINDIR)/test_cxx11_gcm_vaes
endif
ifeq ($(VAES512_SUPPORT),yes)
    BUILD_CHECKS += $(BINDIR)/test_cxx11_gcm_vaes512
endif
ifeq ($(ARM_CRYPTO_SUPPORT),yes)
    BUILD_CHECKS += $(BINDIR)/test_cxx11_gcm_armv8
endif

# Source files
GENERIC_SRC = test_generic.cpp
GENERIC_MULTITU_SRC = test_generic_multitu_main.cpp test_generic_multitu.cpp
CXX11_GCM_SRC = test_cxx11_gcm.cpp
AESNI_SRC = test_aes_ni.cpp
VAES_SRC = test_vaes.cpp
VAES512_SRC = test_vaes512.cpp
ARMV8_SRC = test_armv8.cpp
WAES_SRC = test_waes.cpp
COMPARE_SRC = compare_implementations.cpp

# Common dependencies
COMMON_DEPS = test_data.hpp test_utils.hpp test_options.hpp test_known_answers.hpp test_gcm.hpp test_template.hpp test_entry.hpp
WAES_DEPS = test_waes_adapter.hpp test_waes_cross.hpp test_waes_regressions.hpp

.PHONY: all clean check-platform run-all run-generic run-generic-multitu run-aes-ni run-vaes run-vaes512 run-armv8 run-waes cross-compare run-perf-all run-perf-generic run-perf-aes-ni run-perf-vaes run-perf-vaes512 run-perf-armv8 run-perf-waes compare cmp-specific report-generic report-aes-ni report-vaes report-vaes512 report-armv8 report-waes report-all sanitize sanitize-generic sanitize-waes

all: check-platform $(BINS) $(BUILD_CHECKS)

check-platform:
	@echo "Platform Detection:"
	@echo "  OS: $(UNAME_S)"
	@echo "  Architecture: $(UNAME_M)"
	@echo "  Detected Platform: $(PLATFORM)"
ifeq ($(PLATFORM),x86_64)
	@echo "  AES-NI Support: $(AES_NI_SUPPORT)"
	@echo "  PCLMUL Support: $(PCLMUL_SUPPORT)"
	@echo "  VAES Support: $(VAES_SUPPORT)"
	@echo "  VAES512 Support: $(VAES512_SUPPORT)"
	@if [ "$(VAES512_SUPPORT)" = "yes" ]; then \
		echo "  Building: Generic, WAes, AES-NI, VAES, VAES512 tests"; \
	elif [ "$(VAES_SUPPORT)" = "yes" ]; then \
		echo "  Building: Generic, WAes, AES-NI, VAES tests"; \
	elif [ "$(AES_NI_SUPPORT)" = "yes" ]; then \
		echo "  Building: Generic, WAes, AES-NI tests"; \
	else \
		echo "  Building: Generic and WAes tests"; \
	fi
else ifeq ($(PLATFORM),arm64)
	@echo "  ARM Crypto Support: $(ARM_CRYPTO_SUPPORT)"
	@if [ "$(ARM_CRYPTO_SUPPORT)" = "yes" ]; then \
		echo "  Building: Generic, WAes, ARMv8 tests"; \
	else \
		echo "  Building: Generic and WAes tests"; \
	fi
else
	@echo "  Building: Generic and WAes tests (fallback)"
endif
	@echo ""

$(BINDIR)/test_generic: $(GENERIC_SRC) $(COMMON_DEPS) ../WAes-gen.hpp
	@mkdir -p $(BINDIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $(GENERIC_SRC)

$(BINDIR)/test_generic_multitu: $(GENERIC_MULTITU_SRC) ../WAes-gen.hpp
	@mkdir -p $(BINDIR)
	$(CXX) $(CXX11FLAGS) $(INCLUDES) -o $@ $(GENERIC_MULTITU_SRC)

$(BINDIR)/test_cxx11_gcm_generic: $(CXX11_GCM_SRC) ../WAes-gen.hpp
	@mkdir -p $(BINDIR)
	$(CXX) $(CXX11FLAGS) $(INCLUDES) -o $@ $(CXX11_GCM_SRC)

$(BINDIR)/test_cxx11_gcm_aes_ni: $(CXX11_GCM_SRC) ../WAes-ni.hpp
	@mkdir -p $(BINDIR)
	$(CXX) $(CXX11FLAGS) $(AESNI_FLAGS) $(INCLUDES) -DWAES_TEST_AES_NI -o $@ $(CXX11_GCM_SRC)

$(BINDIR)/test_cxx11_gcm_vaes: $(CXX11_GCM_SRC) ../WAes-vaes.hpp
	@mkdir -p $(BINDIR)
	$(CXX) $(CXX11FLAGS) $(VAES_FLAGS) $(INCLUDES) -DWAES_TEST_VAES -o $@ $(CXX11_GCM_SRC)

$(BINDIR)/test_cxx11_gcm_vaes512: $(CXX11_GCM_SRC) ../WAes-vaes512.hpp
	@mkdir -p $(BINDIR)
	$(CXX) $(CXX11FLAGS) $(VAES512_FLAGS) $(INCLUDES) -DWAES_TEST_VAES512 -o $@ $(CXX11_GCM_SRC)

$(BINDIR)/test_cxx11_gcm_armv8: $(CXX11_GCM_SRC) ../WAes-armv8.hpp
	@mkdir -p $(BINDIR)
	$(CXX) $(CXX11FLAGS) $(ARM_CRYPTO_FLAGS) $(INCLUDES) -DWAES_TEST_ARMV8 -o $@ $(CXX11_GCM_SRC)

$(BINDIR)/test_aes_ni: $(AESNI_SRC) $(COMMON_DEPS) ../WAes-ni.hpp
ifeq ($(AES_NI_SUPPORT),yes)
	@mkdir -p $(BINDIR)
	$(CXX) $(CXXFLAGS) $(AESNI_FLAGS) $(INCLUDES) -o $@ $(AESNI_SRC)
else
	@echo "Skipping AES-NI test - no AES-NI support detected"
endif

$(BINDIR)/test_vaes: $(VAES_SRC) $(COMMON_DEPS) ../WAes-vaes.hpp
ifeq ($(VAES_SUPPORT),yes)
	@mkdir -p $(BINDIR)
	$(CXX) $(CXXFLAGS) $(VAES_FLAGS) $(INCLUDES) -o $@ $(VAES_SRC)
else
	@echo "Skipping VAES test - no VAES support detected"
endif

$(BINDIR)/test_vaes512: $(VAES512_SRC) $(COMMON_DEPS) ../WAes-vaes512.hpp
ifeq ($(VAES512_SUPPORT),yes)
	@mkdir -p $(BINDIR)
	$(CXX) $(CXXFLAGS) $(VAES512_FLAGS) $(INCLUDES) -o $@ $(VAES512_SRC)
else
	@echo "Skipping VAES512 test - no VAES512 support detected"
endif

$(BINDIR)/test_armv8: $(ARMV8_SRC) $(COMMON_DEPS) ../WAes-armv8.hpp
ifeq ($(PLATFORM),arm64)
ifeq ($(ARM_CRYPTO_SUPPORT),yes)
	@mkdir -p $(BINDIR)
	$(CXX) $(CXXFLAGS) $(ARM_CRYPTO_FLAGS) $(INCLUDES) -o $@ $(ARMV8_SRC)
else
	@echo "Skipping ARMv8 test - no ARM crypto support detected"
endif
else
	@echo "Skipping ARMv8 test - not available on $(PLATFORM) platform"
endif

$(BINDIR)/test_waes: $(WAES_SRC) $(COMMON_DEPS) $(WAES_DEPS) ../WAes.hpp
	@mkdir -p $(BINDIR)
	$(CXX) $(CXXFLAGS) $(WAES_TARGET_FLAGS) $(INCLUDES) -o $@ $(WAES_SRC)

$(BINDIR)/test_generic_sanitize: $(GENERIC_SRC) $(COMMON_DEPS) ../WAes-gen.hpp
	@mkdir -p $(BINDIR)
	$(CXX) $(filter-out -O3,$(CXXFLAGS)) $(SANITIZER_FLAGS) $(INCLUDES) -o $@ $(GENERIC_SRC)

$(BINDIR)/test_waes_sanitize: $(WAES_SRC) $(COMMON_DEPS) $(WAES_DEPS) ../WAes.hpp
	@mkdir -p $(BINDIR)
	$(CXX) $(filter-out -O3,$(CXXFLAGS)) $(SANITIZER_FLAGS) $(INCLUDES) -o $@ $(WAES_SRC)

sanitize-generic: $(BINDIR)/test_generic_sanitize
	./$(BINDIR)/test_generic_sanitize

sanitize-waes: $(BINDIR)/test_waes_sanitize
	./$(BINDIR)/test_waes_sanitize

sanitize: sanitize-generic sanitize-waes

# Build comparison tool
compare: $(BINDIR)/compare-implementations

$(BINDIR)/compare-implementations: $(COMPARE_SRC)
	@mkdir -p $(BINDIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $(COMPARE_SRC)

# Run individual functionality tests
run-generic: $(BINDIR)/test_generic
	@echo "=== Running Generic Implementation Tests ==="
	./$(BINDIR)/test_generic

run-generic-multitu: $(BINDIR)/test_generic_multitu
	@echo "=== Running Generic C++11 Multi-TU Link Test ==="
	./$(BINDIR)/test_generic_multitu

run-aes-ni: $(BINDIR)/test_aes_ni
ifeq ($(AES_NI_SUPPORT),yes)
	@echo "=== Running AES-NI Implementation Tests ==="
	./$(BINDIR)/test_aes_ni
else
	@echo "AES-NI tests not available - no AES-NI support detected"
endif

run-vaes: $(BINDIR)/test_vaes
ifeq ($(VAES_SUPPORT),yes)
	@echo "=== Running VAES Implementation Tests ==="
	./$(BINDIR)/test_vaes
else
	@echo "VAES tests not available - no VAES support detected"
endif

run-vaes512: $(BINDIR)/test_vaes512
ifeq ($(VAES512_SUPPORT),yes)
	@echo "=== Running VAES512 Implementation Tests ==="
	./$(BINDIR)/test_vaes512
else
	@echo "VAES512 tests not available - no VAES512 support detected"
endif

run-armv8: $(BINDIR)/test_armv8
ifeq ($(PLATFORM),arm64)
	@echo "=== Running ARMv8 Implementation Tests ==="
	./$(BINDIR)/test_armv8
else
	@echo "ARMv8 tests not available - not available on $(PLATFORM) platform"
endif

run-waes: $(BINDIR)/test_waes
	@echo "=== Running Unified (WAes.hpp) Implementation Tests ==="
	./$(BINDIR)/test_waes

# Run individual performance tests
run-perf-generic: $(BINDIR)/test_generic
	@echo "=== Running Generic Performance Tests ==="
	./$(BINDIR)/test_generic perf

run-perf-aes-ni: $(BINDIR)/test_aes_ni
ifeq ($(AES_NI_SUPPORT),yes)
	@echo "=== Running AES-NI Performance Tests ==="
	./$(BINDIR)/test_aes_ni perf
else
	@echo "AES-NI performance tests not available - no AES-NI support detected"
endif

run-perf-vaes: $(BINDIR)/test_vaes
ifeq ($(VAES_SUPPORT),yes)
	@echo "=== Running VAES Performance Tests ==="
	./$(BINDIR)/test_vaes perf
else
	@echo "VAES performance tests not available - no VAES support detected"
endif

run-perf-vaes512: $(BINDIR)/test_vaes512
ifeq ($(VAES512_SUPPORT),yes)
	@echo "=== Running VAES512 Performance Tests ==="
	./$(BINDIR)/test_vaes512 perf
else
	@echo "VAES512 performance tests not available - no VAES512 support detected"
endif

run-perf-armv8: $(BINDIR)/test_armv8
ifeq ($(PLATFORM),arm64)
	@echo "=== Running ARMv8 Performance Tests ==="
	./$(BINDIR)/test_armv8 perf
else
	@echo "ARMv8 performance tests not available - not available on $(PLATFORM) platform"
endif

run-perf-waes: $(BINDIR)/test_waes
	@echo "=== Running Unified (WAes.hpp) Performance Tests ==="
	./$(BINDIR)/test_waes perf

# Run all functionality tests
run-all: $(BINS) $(BUILD_CHECKS)
	@echo "=== Running All AES Implementation Tests ==="
	@echo ""
	@$(MAKE) run-generic-multitu
	@echo ""
	@$(MAKE) run-generic
	@echo ""
ifeq ($(AES_NI_SUPPORT),yes)
	@$(MAKE) run-aes-ni
	@echo ""
endif
ifeq ($(VAES_SUPPORT),yes)
	@$(MAKE) run-vaes
	@echo ""
endif
ifeq ($(VAES512_SUPPORT),yes)
	@$(MAKE) run-vaes512
	@echo ""
endif
ifeq ($(PLATFORM),arm64)
	@$(MAKE) run-armv8
	@echo ""
endif
	@$(MAKE) run-waes
	@echo ""
	@echo "=== All Functionality Tests Completed ==="

# Run all performance tests
run-perf-all: $(BINS)
	@echo "=== Running All Performance Benchmarks ==="
	@echo ""
	@$(MAKE) run-perf-generic
	@echo ""
ifeq ($(AES_NI_SUPPORT),yes)
	@$(MAKE) run-perf-aes-ni
	@echo ""
endif
ifeq ($(VAES_SUPPORT),yes)
	@$(MAKE) run-perf-vaes
	@echo ""
endif
ifeq ($(VAES512_SUPPORT),yes)
	@$(MAKE) run-perf-vaes512
	@echo ""
endif
ifeq ($(PLATFORM),arm64)
	@$(MAKE) run-perf-armv8
	@echo ""
endif
	@$(MAKE) run-perf-waes
	@echo ""
	@echo "=== All Performance Tests Completed ==="

# Concise output, while still running each complete suite. pipefail preserves
# the test executable's exit status through tail.
quick-test: $(BINS) $(BUILD_CHECKS)
	@echo "=== Quick Test ==="
	@echo "Testing Generic C++11 multi-TU link and GCM API..."
	@./$(BINDIR)/test_generic_multitu
	@./$(BINDIR)/test_cxx11_gcm_generic
	@echo "Testing Generic implementation..."
	@./$(BINDIR)/test_generic | tail -8
ifeq ($(PLATFORM),x86_64)
ifeq ($(AES_NI_SUPPORT),yes)
	@echo ""
	@echo "Testing AES-NI implementation..."
	@./$(BINDIR)/test_aes_ni | tail -8
endif
ifeq ($(VAES_SUPPORT),yes)
	@echo ""
	@echo "Testing VAES implementation..."
	@./$(BINDIR)/test_vaes | tail -8
endif
ifeq ($(VAES512_SUPPORT),yes)
	@echo ""
	@echo "Testing VAES512 implementation..."
	@./$(BINDIR)/test_vaes512 | tail -8
endif
else ifeq ($(PLATFORM),arm64)
ifeq ($(ARM_CRYPTO_SUPPORT),yes)
	@echo ""
	@echo "Testing ARMv8 implementation..."
	@./$(BINDIR)/test_armv8 | tail -8
endif
endif
	@echo ""
	@echo "Testing Unified (WAes.hpp) implementation..."
	@./$(BINDIR)/test_waes | tail -12

# Cross-implementation comparison
cross-compare: $(BINS) $(BINDIR)/compare-implementations
	@echo "=== Running Cross-Implementation Comparison ==="
	@mkdir -p $(REPORTDIR)
	TEST_OUTPUT_DIR=$(REPORTDIR) ./$(BINDIR)/compare-implementations

# Cross-implementation comparison with specific implementations
cmp-specific: $(BINS) $(BINDIR)/compare-implementations
	@echo "=== Running Cross-Implementation Comparison (Specific) ==="
	@echo "Usage: make cmp-specific IMPLS='Generic AES-NI'"
	@if [ -z "$(IMPLS)" ]; then \
		echo "Error: Please specify IMPLS variable"; \
		echo "Example: make cmp-specific IMPLS='Generic AES-NI'"; \
		exit 1; \
	fi
	@mkdir -p $(REPORTDIR)
	TEST_OUTPUT_DIR=$(REPORTDIR) ./$(BINDIR)/compare-implementations $(IMPLS)

# Generate test reports (functionality + performance, saved to out/reports/ with timestamp)
report-generic: $(BINDIR)/test_generic
	@mkdir -p $(REPORTDIR)
	@echo "=== Generating Generic Report: $(REPORTDIR)/Generic_$(TIMESTAMP).txt ==="
	./$(BINDIR)/test_generic 2>&1 | tee $(REPORTDIR)/Generic_$(TIMESTAMP).txt
	./$(BINDIR)/test_generic perf 2>&1 | tee -a $(REPORTDIR)/Generic_$(TIMESTAMP).txt

report-aes-ni: $(BINDIR)/test_aes_ni
	@mkdir -p $(REPORTDIR)
	@echo "=== Generating AES-NI Report: $(REPORTDIR)/AES-NI_$(TIMESTAMP).txt ==="
	./$(BINDIR)/test_aes_ni 2>&1 | tee $(REPORTDIR)/AES-NI_$(TIMESTAMP).txt
	./$(BINDIR)/test_aes_ni perf 2>&1 | tee -a $(REPORTDIR)/AES-NI_$(TIMESTAMP).txt

report-vaes: $(BINDIR)/test_vaes
ifeq ($(VAES_SUPPORT),yes)
	@mkdir -p $(REPORTDIR)
	@echo "=== Generating VAES Report: $(REPORTDIR)/VAES_$(TIMESTAMP).txt ==="
	./$(BINDIR)/test_vaes 2>&1 | tee $(REPORTDIR)/VAES_$(TIMESTAMP).txt
	./$(BINDIR)/test_vaes perf 2>&1 | tee -a $(REPORTDIR)/VAES_$(TIMESTAMP).txt
else
	@echo "VAES report not available - no VAES support detected"
endif

report-vaes512: $(BINDIR)/test_vaes512
ifeq ($(VAES512_SUPPORT),yes)
	@mkdir -p $(REPORTDIR)
	@echo "=== Generating VAES512 Report: $(REPORTDIR)/VAES512_$(TIMESTAMP).txt ==="
	./$(BINDIR)/test_vaes512 2>&1 | tee $(REPORTDIR)/VAES512_$(TIMESTAMP).txt
	./$(BINDIR)/test_vaes512 perf 2>&1 | tee -a $(REPORTDIR)/VAES512_$(TIMESTAMP).txt
else
	@echo "VAES512 report not available - no VAES512 support detected"
endif

report-armv8: $(BINDIR)/test_armv8
ifeq ($(PLATFORM),arm64)
	@mkdir -p $(REPORTDIR)
	@echo "=== Generating ARMv8 Report: $(REPORTDIR)/ARMv8_$(TIMESTAMP).txt ==="
	./$(BINDIR)/test_armv8 2>&1 | tee $(REPORTDIR)/ARMv8_$(TIMESTAMP).txt
	./$(BINDIR)/test_armv8 perf 2>&1 | tee -a $(REPORTDIR)/ARMv8_$(TIMESTAMP).txt
else
	@echo "ARMv8 report not available - not available on $(PLATFORM) platform"
endif

report-waes: $(BINDIR)/test_waes
	@mkdir -p $(REPORTDIR)
	@echo "=== Generating Unified (WAes.hpp) Report: $(REPORTDIR)/WAes_$(TIMESTAMP).txt ==="
	./$(BINDIR)/test_waes 2>&1 | tee $(REPORTDIR)/WAes_$(TIMESTAMP).txt
	./$(BINDIR)/test_waes perf 2>&1 | tee -a $(REPORTDIR)/WAes_$(TIMESTAMP).txt

report-all: $(BINS)
	@echo "=== Generating All Reports ==="
	@$(MAKE) report-generic
ifeq ($(PLATFORM),x86_64)
ifeq ($(AES_NI_SUPPORT),yes)
	@$(MAKE) report-aes-ni
endif
ifeq ($(VAES_SUPPORT),yes)
	@$(MAKE) report-vaes
endif
ifeq ($(VAES512_SUPPORT),yes)
	@$(MAKE) report-vaes512
endif
else ifeq ($(PLATFORM),arm64)
ifeq ($(ARM_CRYPTO_SUPPORT),yes)
	@$(MAKE) report-armv8
endif
endif
	@$(MAKE) report-waes
	@echo "=== All Reports Saved to $(REPORTDIR)/ ==="

clean:
	rm -rf $(OUTDIR)

# Help target
help:
	@echo "Available targets:"
	@echo ""
	@echo "Build:"
	@echo "  all               - Build all tests to $(BINDIR)/"
	@echo "  compare           - Build comparison tool to $(BINDIR)/"
	@echo ""
	@echo "Run (stdout only):"
	@echo "  run-all           - Run all functionality tests"
	@echo "  run-generic-multitu - Run Generic C++11 multi-TU link test"
	@echo "  run-generic       - Run generic implementation test"
	@echo "  run-aes-ni        - Run AES-NI implementation test"
	@echo "  run-vaes          - Run VAES implementation test"
	@echo "  run-vaes512       - Run VAES512 implementation test"
	@echo "  run-armv8         - Run ARMv8 implementation test"
	@echo "  run-waes          - Run Unified (WAes.hpp) implementation test"
	@echo "  run-perf-all      - Run all performance benchmarks"
	@echo "  run-perf-generic  - Run generic performance benchmark"
	@echo "  run-perf-aes-ni   - Run AES-NI performance benchmark"
	@echo "  run-perf-vaes     - Run VAES performance benchmark"
	@echo "  run-perf-vaes512  - Run VAES512 performance benchmark"
	@echo "  run-perf-armv8    - Run ARMv8 performance benchmark"
	@echo "  run-perf-waes     - Run Unified (WAes.hpp) performance benchmark"
	@echo ""
	@echo "Reports (saved to $(REPORTDIR)/<Impl>_<timestamp>.txt):"
	@echo "  report-all        - Generate reports for all implementations"
	@echo "  report-generic    - Generate Generic report (func + perf)"
	@echo "  report-aes-ni     - Generate AES-NI report (func + perf)"
	@echo "  report-vaes       - Generate VAES report (func + perf)"
	@echo "  report-vaes512    - Generate VAES512 report (func + perf)"
	@echo "  report-armv8      - Generate ARMv8 report (func + perf)"
	@echo "  report-waes       - Generate Unified (WAes.hpp) report (func + perf)"
	@echo ""
	@echo "Comparison:"
	@echo "  cross-compare     - Run cross-implementation comparison"
	@echo "  cmp-specific      - Compare specific implementations"
	@echo "                      Usage: make cmp-specific IMPLS='Generic AES-NI'"
	@echo ""
	@echo "Other:"
	@echo "  quick-test        - Run quick test with limited output"
	@echo "  sanitize          - Run Generic and baseline WAes with ASan/UBSan"
	@echo "  sanitize-generic  - Run Generic with ASan/UBSan"
	@echo "  sanitize-waes     - Run baseline WAes with ASan/UBSan"
	@echo "  check-platform    - Check platform detection"
	@echo "  clean             - Remove all build output (rm -rf $(OUTDIR))"
	@echo "  help              - Show this help message"
