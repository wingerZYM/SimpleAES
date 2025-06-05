#include "../WAes-armv8.hpp"
#include "test_template.hpp"

int main(int argc, char* argv[]) {
    // Process command line arguments
    processCommandLineArgs(argc, argv);
    
    std::cout << "AES Library Test Suite - ARMv8 Implementation" << std::endl;
    std::cout << "=============================================" << std::endl;
    
    if (shouldWriteToFile()) {
        std::cout << "File output enabled - results will be saved for comparison" << std::endl;
    }
    
    bool runPerf = false;
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "perf") {
            runPerf = true;
            break;
        }
    }
    
    if (runPerf) {
        runPerformanceTests("ARMv8");
    } else {
        runImplementationTests("ARMv8");
    }
    
    return 0;
} 