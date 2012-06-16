/*
 * Copyright 2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author Venkat Peri. RemoteReality Corp. 
 */

#include <ShmAllocator.h>
#include <gtest/gtest.h>


/// <summary>
///     allocate(0) should return null
/// </summary>
///
TEST(ShmAllocator, allocating_zero_items_will_return_null_pointer)
{
    ShmAllocator<char> allocator;

    ASSERT_STREQ(NULL, allocator.allocate(0, "abc") );
}

/// <summary>
///     allocate(1) should return a valid pointer
/// </summary>
///
TEST(ShmAllocator, no_issue_allocating_one_item)
{
    ShmAllocator<char> allocator;

    ASSERT_STRNE(NULL, allocator.allocate(1, "abc") );
}

/// <summary>
///     allocate(x, null) should throw an exception
/// </summary>
///
TEST(ShmAllocator, allocating_with_a_null_or_bad_name_is_bad)
{
    ShmAllocator<char> allocator;

    EXPECT_ANY_THROW(allocator.allocate(1, 0) );
}

/// <summary>
///     No equality between two allocators (since they are stateful)
/// </summary>
///
TEST(ShmAllocator, no_two_allocators_are_equal_by_design)
{
    EXPECT_NE(ShmAllocator<char>( ), ShmAllocator<char>( ) );
}

/// <summary>
///     deallocate on allocate(1) should be fine
/// </summary>
///
TEST(ShmAllocator, deallocate_on_good_data_is_ok)
{
    ShmAllocator<char> allocator;
    auto               x = allocator.allocate(1, "abc");
    ASSERT_STRNE(NULL, x);
    ASSERT_NO_THROW(allocator.deallocate(x) );
}

/// <summary>
///     deallocate on a null should fail
/// </summary>
///
TEST(ShmAllocator, deallocate_on_null_is_bad)
{
    ShmAllocator<char> allocator;
    auto               x = allocator.allocate(1, "abc");
    ASSERT_STRNE(NULL, x);
    ASSERT_ANY_THROW(allocator.deallocate(0) );
}

/// <summary>
///     deallocate by a second allocator should fail
/// </summary>
///
TEST(ShmAllocator, deallocating_from_another_alloc_is_bad)
{
    ShmAllocator<char> allocator1;
    ShmAllocator<char> allocator2;
    auto               x1 = allocator1.allocate(1, "abc1");
    auto               x2 = allocator2.allocate(1, "abc2");

    ASSERT_STRNE(NULL, x1);
    ASSERT_STRNE(NULL, x2);

    ASSERT_ANY_THROW(allocator1.deallocate(x2) );
    ASSERT_ANY_THROW(allocator2.deallocate(x1) );
}

/// <summary>
///     Two allocators that point to the same shared mem, share the same memory
/// </summary>
///
TEST(ShmAllocator, two_allocators_on_the_same_mem_see_the_same)
{
    ShmAllocator<char> allocator1;
    ShmAllocator<char> allocator2;
    auto               x1 = allocator1.allocate(100, "abc");
    auto               x2 = allocator2.allocate(100, "abc");

    ASSERT_STRNE(NULL, x1);
    ASSERT_STRNE(NULL, x2);

    memset(x1, 0xaa, 50);
    EXPECT_EQ(memcmp(x2, x1, 50), 0);

    for ( int i = 0; i < 50; i++ )
    {
        x1[i] = 50 - i;
    }

    for ( int i = 0; i < 50; i++ )
    {
        EXPECT_EQ( (unsigned char) x2[i], 50 - i);
    }

    memset(x1, 0x55, 50);
    EXPECT_EQ(memcmp(x2, x1, 50), 0);
}

static int gExceptionCode = 0;

int filter(unsigned int code, struct _EXCEPTION_POINTERS *ep) 
{
    gExceptionCode = code;
    //std::cout << "OS Exception caught : " << hex(code);
    return EXCEPTION_EXECUTE_HANDLER;
}

int memcpy_to_null_is_bad(char *addr)
{
    //invalid memory, should fail with an OS exception. Needs special handling
    __try
    {
        memset(addr, 0x55, 50);
    }
    __except(filter(GetExceptionCode(), GetExceptionInformation()))
    {
        return GetExceptionCode();
    }

    return 0;
}

/// <summary>
///     Given two allocators that point to the same shared mem, if one does, the other can still access the memory
/// </summary>
///
TEST(ShmAllocator, memcpy_to_bad_address_is_bad)
{
    EXPECT_NE(memcpy_to_null_is_bad(0), 0);
}

/// <summary>
///     Given two allocators that point to the same shared mem, if one does, the other can still access the memory
/// </summary>
///
TEST(ShmAllocator, using_alloc_after_its_gone_is_bad)
{
    ShmAllocator<char> allocator1;
    auto               x1 = allocator1.allocate(100, "abc");

    allocator1.deallocate(x1);
    
    EXPECT_NE(memcpy_to_null_is_bad(x1), 0);
}


/// <summary>
///     Given two allocators that point to the same shared mem, if one does, the other can still access the memory
/// </summary>
///
TEST(ShmAllocator, if_one_dies_the_other_alloc_can_still_use_mem)
{
    ShmAllocator<char> allocator1;
    ShmAllocator<char> allocator2;
    auto               x1 = allocator1.allocate(100, "abc");
    auto               x2 = allocator2.allocate(100, "abc");

    allocator1.deallocate(x1);

    EXPECT_NE(memcpy_to_null_is_bad(x1), 0);
    EXPECT_EQ(memcpy_to_null_is_bad(x2), 0);
}

