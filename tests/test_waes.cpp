#include "../WAes.hpp"
#include "test_waes_adapter.hpp"

// CWAes must be defined before the shared standalone-header suite is included.
#include "test_template.hpp"
#include "test_waes_cross.hpp"
#include "test_waes_regressions.hpp"

#include <iostream>
#include <string>

namespace {

bool runBackend(WAes::Backend backend, const TestOptions &options) {
  g_testBackend = backend;
  const std::string implementationName =
      backend == WAes::Backend::Auto
          ? "WAes"
          : std::string("WAes(") + WAes::GetImplName(backend) + ')';

  std::cout << "AES Library Test Suite - " << implementationName << '\n'
            << "===============================================\n";

  if (options.runPerformance)
    return runPerformanceTests(implementationName, options);
  return runImplementationTests(implementationName, options).success();
}

bool parseBackend(int argc, char *argv[], WAes::Backend &backend,
                  bool &hasForcedBackend) {
  for (int i = 1; i < argc; ++i) {
    if (std::string(argv[i]) != "--backend")
      continue;
    if (i + 1 >= argc) {
      std::cerr << "Missing value after --backend\n";
      return false;
    }

    const std::string requested = argv[++i];
    for (auto available : WAes::AvailableBackends()) {
      if (requested == WAes::GetImplName(available)) {
        backend = available;
        hasForcedBackend = true;
        break;
      }
    }

    if (!hasForcedBackend) {
      std::cerr << "Unknown or unavailable backend: " << requested
                << "\nAvailable:";
      for (auto available : WAes::AvailableBackends())
        std::cerr << ' ' << WAes::GetImplName(available);
      std::cerr << '\n';
      return false;
    }
  }
  return true;
}

} // namespace

int main(int argc, char *argv[]) {
  const TestOptions options = parseTestOptions(argc, argv);
  if (!options.valid)
    return 2;
  if (options.showHelp) {
    printTestHelp(argv[0]);
    std::cout
        << "  --backend <name>                 Test one unified backend\n";
    return 0;
  }

  WAes::Backend forcedBackend = WAes::Backend::Auto;
  bool hasForcedBackend = false;
  if (!parseBackend(argc, argv, forcedBackend, hasForcedBackend))
    return 2;

  bool successful = true;
  if (hasForcedBackend) {
    successful = runBackend(forcedBackend, options);
  } else if (shouldWriteToFile(options)) {
    successful = runBackend(WAes::Backend::Auto, options);
  } else {
    for (auto backend : WAes::AvailableBackends()) {
      successful = runBackend(backend, options) && successful;
      std::cout << '\n';
    }
    if (!options.runPerformance)
      successful = WAesCrossTests::run() && successful;
  }

  if (!options.runPerformance)
    successful = WAesRegressionTests::run() && successful;
  return successful ? 0 : 1;
}
