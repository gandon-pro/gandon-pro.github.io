#pragma once
namespace gandon {
// Presents an explicit opt-in prompt. No installation occurs on No/close.
// Returns true only when the expected device/protocol is available.
bool offer_memory_driver_setup(void* owner);
}
