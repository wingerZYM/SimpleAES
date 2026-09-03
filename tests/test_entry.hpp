#pragma once

#include "test_template.hpp"

#include <iostream>
#include <string>

inline int runStandaloneTestMain(int argc, char *argv[],
                                 const std::string &implementationName) {
  const TestOptions options = parseTestOptions(argc, argv);
  if (!options.valid) {
    return 2;
  }
  if (options.showHelp) {
    printTestHelp(argv[0]);
    return 0;
  }

  std::cout << "AES Library Test Suite - " << implementationName << '\n'
            << "===============================================\n";
  if (shouldWriteToFile(options)) {
    std::cout << "File output enabled - results will be saved for comparison\n";
  }

  if (options.runPerformance) {
    return runPerformanceTests(implementationName, options) ? 0 : 1;
  }

  return runImplementationTests(implementationName, options).success() ? 0 : 1;
}
