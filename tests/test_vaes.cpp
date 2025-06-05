#include "../WAes-vaes.hpp"
#include "test_template.hpp"

int main(int argc, char* argv[]) {
    // Process command line arguments
    processCommandLineArgs(argc, argv);
    
    std::cout << "AES Library Test Suite - VAES Implementation" << std::endl;
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
        runPerformanceTests("VAES");
    } else {
        runImplementationTests("VAES");
    }
    
    return 0;
} 