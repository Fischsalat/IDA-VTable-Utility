#include <cstdio>
#include <cstdint>

namespace
{

volatile int g_multiplier = 3;
volatile int g_vtable_addend = 0;
const char g_result_format[] = "result: %d\n";

using VftJumpType = void;
using value_transform_t = int (*)(int);
using demo_method_t = int (*)(VftJumpType *, volatile int *, value_transform_t);

__declspec(noinline) int scale_value(int value);

struct demo_vtable_t
{
  demo_method_t methods[3];
};

struct SomeTypeStorage
{
  demo_vtable_t *vtable;
  int value;
};

__declspec(noinline) int demo_method_0(
    VftJumpType *self,
    volatile int *addend,
    value_transform_t transform)
{
  return transform(reinterpret_cast<SomeTypeStorage *>(self)->value) + *addend;
}

__declspec(noinline) int demo_method_1(
    VftJumpType *self,
    volatile int *addend,
    value_transform_t transform)
{
  return transform(reinterpret_cast<SomeTypeStorage *>(self)->value) - *addend;
}

__declspec(noinline) int demo_method_2(
    VftJumpType *self,
    volatile int *addend,
    value_transform_t transform)
{
  return transform(reinterpret_cast<SomeTypeStorage *>(self)->value) + *addend;
}

extern "C" demo_method_t VftJumpType_vft[3] =
{
  demo_method_0,
  demo_method_1,
  demo_method_2,
};

__declspec(noinline) int scale_value(int value)
{
  return value * g_multiplier;
}

__declspec(noinline) int combine_values(int left, int right)
{
  return scale_value(left) + scale_value(right);
}

__declspec(noinline) void print_result(int value)
{
  std::printf(g_result_format, value);
}

__declspec(noinline) int invoke_vtable_slot_2(VftJumpType *object)
{
  auto storage = reinterpret_cast<SomeTypeStorage *>(object);
  auto address = reinterpret_cast<unsigned char *>(storage->vtable)
               + 2 * sizeof(demo_method_t);
  auto method = *reinterpret_cast<demo_method_t *>(address);
  return method(object, &g_vtable_addend, scale_value);
}

#pragma optimize("", on)
__declspec(noinline) int invoke_raw_vtable_slot_2(VftJumpType *object)
{
  const auto vtable = *reinterpret_cast<std::uintptr_t *>(object);
  const auto method = *reinterpret_cast<demo_method_t *>(vtable + 0x10);
  return method(object, &g_vtable_addend, scale_value);
}
#pragma optimize("", off)

} // namespace

int main()
{
  SomeTypeStorage object_storage =
  {
    reinterpret_cast<demo_vtable_t *>(VftJumpType_vft),
    13,
  };
  auto object = reinterpret_cast<VftJumpType *>(&object_storage);
  const int first = combine_values(4, 7);
  const int second = combine_values(first, 2);
  const int virtual_result = invoke_vtable_slot_2(object);
  const int raw_virtual_result = invoke_raw_vtable_slot_2(object);
  print_result(first);
  print_result(second);
  print_result(virtual_result);
  print_result(raw_virtual_result);
  return second == 105 && virtual_result == 39 && raw_virtual_result == 39
       ? 0
       : 1;
}
