CXX = g++
CXXFLAGS = -std=c++17 -O3 -march=native -Wall -Wextra
INCLUDES = -I..

# Output directories
OUTDIR = out
BINDIR = $(OUTDIR)/bin
REPORTDIR = $(OUTDIR)/reports
TIMESTAMP := $(shell date +%Y%m%d_%H%M%S)

# Platform detection
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

# Check for x86_64 and VAES support (requires AVX2 + VAES)
ifeq ($(UNAME_M),x86_64)
    PLATFORM = x86_64
    VAES_SUPPORT := $(shell echo | $(CXX) -march=native -dM -E - | grep -q "__AVX2__" && echo | $(CXX) -march=native -dM -E - | grep -q "__VAES__" && echo "yes" || echo "no")
    AES_NI_SUPPORT := $(shell echo | $(CXX) -march=native -dM -E - | grep -q "__AES__" && echo "yes" || echo "no")
    # Check for AVX512F support for VAES512
    VAES512_SUPPORT := $(shell echo | $(CXX) -march=native -dM -E - | grep -q "__AVX512F__" && echo | $(CXX) -march=native -dM -E - | grep -q "__VAES__" && echo "yes" || echo "no")
    X86_TESTS = test_generic test_aes_ni test_waes
    ifeq ($(VAES_SUPPORT),yes)
        X86_TESTS += test_vaes
        CXXFLAGS += -DVAES_SUPPORTED
    endif
    ifeq ($(VAES512_SUPPORT),yes)
        X86_TESTS += test_vaes512
        CXXFLAGS += -DVAES512_SUPPORTED
    endif
    TESTS = $(X86_TESTS)
else ifeq ($(UNAME_M),amd64)
    # FreeBSD/Windows uses amd64 instead of x86_64
    PLATFORM = x86_64
    VAES_SUPPORT := $(shell echo | $(CXX) -march=native -dM -E - | grep -q "__AVX2__" && echo | $(CXX) -march=native -dM -E - | grep -q "__VAES__" && echo "yes" || echo "no")
    AES_NI_SUPPORT := $(shell echo | $(CXX) -march=native -dM -E - | grep -q "__AES__" && echo "yes" || echo "no")
    VAES512_SUPPORT := $(shell echo | $(CXX) -march=native -dM -E - | grep -q "__AVX512F__" && echo | $(CXX) -march=native -dM -E - | grep -q "__VAES__" && echo "yes" || echo "no")
    X86_TESTS = test_generic test_aes_ni test_waes
    ifeq ($(VAES_SUPPORT),yes)
        X86_TESTS += test_vaes
        CXXFLAGS += -DVAES_SUPPORTED
    endif
    ifeq ($(VAES512_SUPPORT),yes)
        X86_TESTS += test_vaes512
        CXXFLAGS += -DVAES512_SUPPORTED
    endif
    TESTS = $(X86_TESTS)
else ifeq ($(UNAME_M),aarch64)
    # ARM64 Linux
    PLATFORM = arm64
    ARM_CRYPTO_SUPPORT := $(shell echo | $(CXX) -march=native -dM -E - | grep -q "__ARM_FEATURE_CRYPTO" && echo "yes" || echo "no")
    # x86-64 specific features not available on ARM64
    VAES_SUPPORT = no
    VAES512_SUPPORT = no
    AES_NI_SUPPORT = no
    ARM_TESTS = test_generic test_waes
    ifeq ($(ARM_CRYPTO_SUPPORT),yes)
        ARM_TESTS += test_armv8
        CXXFLAGS += -DARM_CRYPTO_SUPPORTED
    endif
    TESTS = $(ARM_TESTS)
else ifeq ($(UNAME_M),arm64)
    # ARM64 macOS
    PLATFORM = arm64
    # macOS ARM64 always has crypto extensions
    ARM_CRYPTO_SUPPORT = yes
    # x86-64 specific features not available on ARM64
    VAES_SUPPORT = no
    VAES512_SUPPORT = no
    AES_NI_SUPPORT = no
    ARM_TESTS = test_generic test_armv8 test_waes
    CXXFLAGS += -DARM_CRYPTO_SUPPORTED
    TESTS = $(ARM_TESTS)
else
    # Fallback to generic only
    PLATFORM = unknown
    TESTS = test_generic test_waes
    ARM_CRYPTO_SUPPORT = no
    VAES_SUPPORT = no
    VAES512_SUPPORT = no
    AES_NI_SUPPORT = no
endif

# Full paths of test binaries (derived from TESTS list)
BINS = $(addprefix $(BINDIR)/, $(TESTS))

# Source files
GENERIC_SRC = test_generic.cpp
AESNI_SRC = test_aes_ni.cpp
VAES_SRC = test_vaes.cpp
VAES512_SRC = test_vaes512.cpp
ARMV8_SRC = test_armv8.cpp
WAES_SRC = test_waes.cpp
COMPARE_SRC = compare_implementations.cpp

# Common dependencies
COMMON_DEPS = test_data.hpp test_utils.hpp test_template.hpp

.PHONY: all clean check-platform run-all run-generic run-aes-ni run-vaes run-vaes512 run-armv8 run-waes cross-compare run-perf-all run-perf-generic run-perf-aes-ni run-perf-vaes run-perf-vaes512 run-perf-armv8 run-perf-waes compare cmp-specific report-generic report-aes-ni report-vaes report-vaes512 report-armv8 report-waes report-all

all: check-platform $(BINS)

check-platform:
	@echo "Platform Detection:"
	@echo "  OS: $(UNAME_S)"
	@echo "  Architecture: $(UNAME_M)"
	@echo "  Detected Platform: $(PLATFORM)"
ifeq ($(PLATFORM),x86_64)
	@echo "  AES-NI Support: $(AES_NI_SUPPORT)"
	@echo "  VAES Support: $(VAES_SUPPORT)"
	@echo "  VAES512 Support: $(VAES512_SUPPORT)"
	@if [ "$(VAES512_SUPPORT)" = "yes" ]; then \
		echo "  Building: Generic, AES-NI, VAES, VAES512 tests"; \
	elif [ "$(VAES_SUPPORT)" = "yes" ]; then \
		echo "  Building: Generic, AES-NI, VAES tests"; \
	elif [ "$(AES_NI_SUPPORT)" = "yes" ]; then \
		echo "  Building: Generic, AES-NI tests"; \
	else \
		echo "  Building: Generic test only"; \
	fi
else ifeq ($(PLATFORM),arm64)
	@echo "  ARM Crypto Support: $(ARM_CRYPTO_SUPPORT)"
	@if [ "$(ARM_CRYPTO_SUPPORT)" = "yes" ]; then \
		echo "  Building: Generic, ARMv8 tests"; \
	else \
		echo "  Building: Generic test only"; \
	fi
else
	@echo "  Building: Generic test only (fallback)"
endif
	@echo ""

$(BINDIR)/test_generic: $(GENERIC_SRC) $(COMMON_DEPS) ../WAes-gen.hpp
	@mkdir -p $(BINDIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $(GENERIC_SRC)

$(BINDIR)/test_aes_ni: $(AESNI_SRC) $(COMMON_DEPS) ../WAes-ni.hpp
ifeq ($(PLATFORM),x86_64)
	@mkdir -p $(BINDIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $(AESNI_SRC)
else
	@echo "Skipping AES-NI test - not available on $(PLATFORM) platform"
endif

$(BINDIR)/test_vaes: $(VAES_SRC) $(COMMON_DEPS) ../WAes-vaes.hpp
ifeq ($(VAES_SUPPORT),yes)
	@mkdir -p $(BINDIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $(VAES_SRC)
else
	@echo "Skipping VAES test - no VAES support detected"
endif

$(BINDIR)/test_vaes512: $(VAES512_SRC) $(COMMON_DEPS) ../WAes-vaes512.hpp
ifeq ($(VAES512_SUPPORT),yes)
	@mkdir -p $(BINDIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $(VAES512_SRC)
else
	@echo "Skipping VAES512 test - no VAES512 support detected"
endif

$(BINDIR)/test_armv8: $(ARMV8_SRC) $(COMMON_DEPS) ../WAes-armv8.hpp
ifeq ($(PLATFORM),arm64)
ifeq ($(ARM_CRYPTO_SUPPORT),yes)
	@mkdir -p $(BINDIR)
	$(CXX) $(CXXFLAGS) -march=armv8-a+crypto $(INCLUDES) -o $@ $(ARMV8_SRC)
else
	@echo "Skipping ARMv8 test - no ARM crypto support detected"
endif
else
	@echo "Skipping ARMv8 test - not available on $(PLATFORM) platform"
endif

$(BINDIR)/test_waes: $(WAES_SRC) $(COMMON_DEPS) ../WAes.hpp
	@mkdir -p $(BINDIR)
ifeq ($(ARM_CRYPTO_SUPPORT),yes)
	$(CXX) $(CXXFLAGS) -march=armv8-a+crypto $(INCLUDES) -o $@ $(WAES_SRC)
else
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $(WAES_SRC)
endif

# Build comparison tool
compare: $(BINDIR)/compare-implementations

$(BINDIR)/compare-implementations: $(COMPARE_SRC)
	@mkdir -p $(BINDIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $(COMPARE_SRC)

# Run individual functionality tests
run-generic: $(BINDIR)/test_generic
	@echo "=== Running Generic Implementation Tests ==="
	./$(BINDIR)/test_generic

run-aes-ni: $(BINDIR)/test_aes_ni
	@echo "=== Running AES-NI Implementation Tests ==="
	./$(BINDIR)/test_aes_ni

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
	@echo "=== Running AES-NI Performance Tests ==="
	./$(BINDIR)/test_aes_ni perf

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
run-all: $(BINS)
	@echo "=== Running All AES Implementation Tests ==="
	@echo ""
	@$(MAKE) run-generic
	@echo ""
	@$(MAKE) run-aes-ni
	@echo ""
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
	@$(MAKE) run-perf-aes-ni
	@echo ""
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

# Quick test with smaller dataset
quick-test: $(BINS)
	@echo "=== Quick Test ==="
	@echo "Testing Generic implementation..."
	@./$(BINDIR)/test_generic | head -20
ifeq ($(PLATFORM),x86_64)
	@echo ""
	@echo "Testing AES-NI implementation..."
	@./$(BINDIR)/test_aes_ni | head -20
ifeq ($(VAES_SUPPORT),yes)
	@echo ""
	@echo "Testing VAES implementation..."
	@./$(BINDIR)/test_vaes | head -20
endif
ifeq ($(VAES512_SUPPORT),yes)
	@echo ""
	@echo "Testing VAES512 implementation..."
	@./$(BINDIR)/test_vaes512 | head -20
endif
else ifeq ($(PLATFORM),arm64)
ifeq ($(ARM_CRYPTO_SUPPORT),yes)
	@echo ""
	@echo "Testing ARMv8 implementation..."
	@./$(BINDIR)/test_armv8 | head -20
endif
endif
	@echo ""
	@echo "Testing Unified (WAes.hpp) implementation..."
	@./$(BINDIR)/test_waes | head -20

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
	@$(MAKE) report-aes-ni
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
	@echo "  check-platform    - Check platform detection"
	@echo "  clean             - Remove all build output (rm -rf $(OUTDIR))"
	@echo "  help              - Show this help message" 