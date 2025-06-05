CXX = g++
CXXFLAGS = -std=c++17 -O3 -march=native -Wall -Wextra
INCLUDES = -I..

# Platform detection
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

# Check for x86_64 and VAES support (requires AVX2 + AES-NI)
ifeq ($(UNAME_M),x86_64)
    PLATFORM = x86_64
    VAES_SUPPORT := $(shell echo | $(CXX) -march=native -dM -E - | grep -q "__AVX2__" && echo | $(CXX) -march=native -dM -E - | grep -q "__AES__" && echo "yes" || echo "no")
    AES_NI_SUPPORT := $(shell echo | $(CXX) -march=native -dM -E - | grep -q "__AES__" && echo "yes" || echo "no")
    # Check for AVX512F support for VAES512
    VAES512_SUPPORT := $(shell echo | $(CXX) -march=native -dM -E - | grep -q "__AVX512F__" && echo | $(CXX) -march=native -dM -E - | grep -q "__VAES__" && echo "yes" || echo "no")
    X86_TESTS = test_generic test_aes_ni
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
    VAES_SUPPORT := $(shell echo | $(CXX) -march=native -dM -E - | grep -q "__AVX2__" && echo | $(CXX) -march=native -dM -E - | grep -q "__AES__" && echo "yes" || echo "no")
    AES_NI_SUPPORT := $(shell echo | $(CXX) -march=native -dM -E - | grep -q "__AES__" && echo "yes" || echo "no")
    VAES512_SUPPORT := $(shell echo | $(CXX) -march=native -dM -E - | grep -q "__AVX512F__" && echo | $(CXX) -march=native -dM -E - | grep -q "__VAES__" && echo "yes" || echo "no")
    X86_TESTS = test_generic test_aes_ni
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
    ARM_TESTS = test_generic
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
    ARM_TESTS = test_generic test_armv8
    CXXFLAGS += -DARM_CRYPTO_SUPPORTED
    TESTS = $(ARM_TESTS)
else
    # Fallback to generic only
    PLATFORM = unknown
    TESTS = test_generic
    ARM_CRYPTO_SUPPORT = no
    VAES_SUPPORT = no
    AES_NI_SUPPORT = no
endif

# Source files
GENERIC_SRC = test_generic.cpp
AESNI_SRC = test_aes_ni.cpp
VAES_SRC = test_vaes.cpp
VAES512_SRC = test_vaes512.cpp
ARMV8_SRC = test_armv8.cpp

# Common dependencies
COMMON_DEPS = test_data.hpp test_utils.hpp test_template.hpp

.PHONY: all clean check-platform run-all run-generic run-aes-ni run-vaes run-vaes512 run-armv8 run-cross-compare run-perf-all run-perf-generic run-perf-aes-ni run-perf-vaes run-perf-vaes512 run-perf-armv8

all: check-platform $(TESTS)

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

test_generic: $(GENERIC_SRC) $(COMMON_DEPS) ../WAes-gen.hpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $(GENERIC_SRC)

test_aes_ni: $(AESNI_SRC) $(COMMON_DEPS) ../WAes-ni.hpp
ifeq ($(PLATFORM),x86_64)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $(AESNI_SRC)
else
	@echo "Skipping AES-NI test - not available on $(PLATFORM) platform"
endif

test_vaes: $(VAES_SRC) $(COMMON_DEPS) ../WAes-vaes.hpp
ifeq ($(VAES_SUPPORT),yes)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $(VAES_SRC)
else
	@echo "Skipping VAES test - no VAES support detected"
endif

test_vaes512: $(VAES512_SRC) $(COMMON_DEPS) ../WAes-vaes512.hpp
ifeq ($(VAES512_SUPPORT),yes)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $(VAES512_SRC)
else
	@echo "Skipping VAES512 test - no VAES512 support detected"
endif

test_armv8: $(ARMV8_SRC) $(COMMON_DEPS) ../WAes-armv8.hpp
ifeq ($(PLATFORM),arm64)
ifeq ($(ARM_CRYPTO_SUPPORT),yes)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $(ARMV8_SRC)
else
	@echo "Skipping ARMv8 test - no ARM crypto support detected"
endif
else
	@echo "Skipping ARMv8 test - not available on $(PLATFORM) platform"
endif

# Run individual functionality tests
run-generic: test_generic
	@echo "=== Running Generic Implementation Tests ==="
	./test_generic

run-aes-ni: test_aes_ni
	@echo "=== Running AES-NI Implementation Tests ==="
	./test_aes_ni

run-vaes: test_vaes
ifeq ($(VAES_SUPPORT),yes)
	@echo "=== Running VAES Implementation Tests ==="
	./test_vaes
else
	@echo "VAES tests not available - no VAES support detected"
endif

run-vaes512: test_vaes512
ifeq ($(VAES512_SUPPORT),yes)
	@echo "=== Running VAES512 Implementation Tests ==="
	./test_vaes512
else
	@echo "VAES512 tests not available - no VAES512 support detected"
endif

run-armv8: test_armv8
ifeq ($(PLATFORM),arm64)
	@echo "=== Running ARMv8 Implementation Tests ==="
	./test_armv8
else
	@echo "ARMv8 tests not available - not available on $(PLATFORM) platform"
endif

# Run individual performance tests
run-perf-generic: test_generic
	@echo "=== Running Generic Performance Tests ==="
	./test_generic perf

run-perf-aes-ni: test_aes_ni
	@echo "=== Running AES-NI Performance Tests ==="
	./test_aes_ni perf

run-perf-vaes: test_vaes
ifeq ($(VAES_SUPPORT),yes)
	@echo "=== Running VAES Performance Tests ==="
	./test_vaes perf
else
	@echo "VAES performance tests not available - no VAES support detected"
endif

run-perf-vaes512: test_vaes512
ifeq ($(VAES512_SUPPORT),yes)
	@echo "=== Running VAES512 Performance Tests ==="
	./test_vaes512 perf
else
	@echo "VAES512 performance tests not available - no VAES512 support detected"
endif

run-perf-armv8: test_armv8
ifeq ($(PLATFORM),arm64)
	@echo "=== Running ARMv8 Performance Tests ==="
	./test_armv8 perf
else
	@echo "ARMv8 performance tests not available - not available on $(PLATFORM) platform"
endif

# Run all functionality tests
run-all: $(TESTS)
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
	@echo "=== All Functionality Tests Completed ==="

# Run all performance tests
run-perf-all: $(TESTS)
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
	@echo "=== All Performance Tests Completed ==="

# Run everything using shell script
run-complete: $(TESTS)
	@chmod +x run_all_tests.sh
	@./run_all_tests.sh

# Quick test with smaller dataset
quick-test: $(TESTS)
	@echo "=== Quick Test ==="
	@echo "Testing Generic implementation..."
	@./test_generic | head -20
ifeq ($(PLATFORM),x86_64)
	@echo ""
	@echo "Testing AES-NI implementation..."
	@./test_aes_ni | head -20
ifeq ($(VAES_SUPPORT),yes)
	@echo ""
	@echo "Testing VAES implementation..."
	@./test_vaes | head -20
endif
ifeq ($(VAES512_SUPPORT),yes)
	@echo ""
	@echo "Testing VAES512 implementation..."
	@./test_vaes512 | head -20
endif
else ifeq ($(PLATFORM),arm64)
ifeq ($(ARM_CRYPTO_SUPPORT),yes)
	@echo ""
	@echo "Testing ARMv8 implementation..."
	@./test_armv8 | head -20
endif
endif

# Cross-implementation comparison using shell script
run-cross-compare: $(TESTS)
	@echo "=== Running Cross-Implementation Comparison ==="
	@chmod +x run_cross_comparison.sh
	@./run_cross_comparison.sh

# Clean up test result files
clean-results:
	@echo "Cleaning up test result files..."
	@rm -f test_results_*.txt
	@rm -f implementation_comparison_report.txt
	@echo "Test result files cleaned."

clean: clean-results
	rm -f $(TESTS)

# Help target
help:
	@echo "Available targets:"
	@echo "  all               - Build all tests"
	@echo "  test_generic      - Build generic implementation test"
	@echo "  test_aes_ni       - Build AES-NI implementation test"
	@echo "  test_vaes         - Build VAES implementation test (if supported)"
	@echo "  test_vaes512      - Build VAES512 implementation test (if supported)"
	@echo "  test_armv8        - Build ARMv8 implementation test (if supported)"
	@echo "  run-all           - Run all functionality tests"
	@echo "  run-generic       - Run generic implementation test"
	@echo "  run-aes-ni        - Run AES-NI implementation test"
	@echo "  run-vaes          - Run VAES implementation test"
	@echo "  run-vaes512       - Run VAES512 implementation test"
	@echo "  run-armv8         - Run ARMv8 implementation test"
	@echo "  run-cross-compare - Run cross-implementation comparison"
	@echo "  run-perf-all      - Run all performance benchmarks"
	@echo "  run-perf-generic  - Run generic performance benchmark"
	@echo "  run-perf-aes-ni   - Run AES-NI performance benchmark"
	@echo "  run-perf-vaes     - Run VAES performance benchmark"
	@echo "  run-perf-vaes512  - Run VAES512 performance benchmark"
	@echo "  run-perf-armv8    - Run ARMv8 performance benchmark"
	@echo "  run-complete      - Run complete test suite (functionality + performance)"
	@echo "  quick-test        - Run quick test with limited output"
	@echo "  clean             - Remove all built executables and test result files"
	@echo "  clean-results     - Remove only test result files"
	@echo "  check-platform    - Check platform detection"
	@echo "  help              - Show this help message" 