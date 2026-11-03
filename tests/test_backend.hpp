#pragma once

#if defined(WAES_TEST_UNIFIED)
#include "test_waes_adapter.hpp"
#elif defined(WAES_TEST_AES_NI)
#include "../WAes-ni.hpp"
#elif defined(WAES_TEST_VAES)
#include "../WAes-vaes.hpp"
#elif defined(WAES_TEST_VAES512)
#include "../WAes-vaes512.hpp"
#elif defined(WAES_TEST_ARMV8)
#include "../WAes-armv8.hpp"
#else
#include "../WAes-gen.hpp"
#endif
