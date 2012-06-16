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

#pragma once

#include <windows.h>
#include <stddef.h>
#include <new>
#include <stdexcept>

#include <stdlib.h>
#include <ostream>
#include <map>
#include "HexFormat.h"
#include <stdint.h>
#include <sstream>
#include <iosfwd>
#include <iomanip>

#define hex(x)  s << std::setw(8)       \
                << std::setfill('0')    \
                << std::hex << (unsigned long)(x)


/// <summary>
///     std:: style allocator for named page file shared memory
/// </summary>
template<class T>
class ShmAllocator
{
public:
    /// <summary>
    ///     Defines an alias representing the handle map.
    /// </summary>
    typedef std::map<uintptr_t, HANDLE> HandleMap;

    /// <summary>
    ///     Defines an alias representing the pointer.
    /// </summary>
    typedef T * pointer;

    /// <summary>
    ///     Defines an alias representing the constant
    ///     pointer.
    /// </summary>
    typedef const T * const_pointer;

    /// <summary>
    ///     Defines an alias representing the reference.
    /// </summary>
    typedef T &       reference;

    /// <summary>
    ///     Defines an alias representing the constant
    ///     reference.
    /// </summary>
    typedef const T & const_reference;

    /// <summary>
    ///     Defines an alias representing type of the value.
    /// </summary>
    typedef T         value_type;

    /// <summary>
    ///     Defines an alias representing type of the size.
    /// </summary>
    typedef size_t    size_type;

    /// <summary>
    ///     Defines an alias representing type of the
    ///     difference.
    /// </summary>
    typedef ptrdiff_t   difference_type;

    /// <summary>
    ///     Address.
    /// </summary>
    ///
    /// <param name="r">[in,out] The r.</param>
    ///
    /// <returns>
    ///     null if it fails, else.
    /// </returns>
    T *address(T & r) const
    {
        return &r;
    }

    /// <summary>
    ///     Address.
    /// </summary>
    ///
    /// <param name="s">The s.</param>
    ///
    /// <returns>
    ///     null if it fails, else.
    /// </returns>
    const T *address(const T & s) const
    {
        return &s;
    }

    /// <summary>
    ///     Gets the maximum size.
    /// </summary>
    ///
    /// <returns>
    ///     .
    /// </returns>
    size_t max_size( ) const
    {
        // The following has been carefully written to be independent of
        // the definition of size_t and to avoid signed/unsigned warnings.
        return ( static_cast<size_t>( 0 ) - static_cast<size_t>( 1 ) ) / sizeof( T );
    }

    // The following must be the same for all allocators.

    /// <summary>
    ///     Rebind.
    /// </summary>
    template<typename U>
    struct rebind
    {
        typedef ShmAllocator<U>   other;
    };

    /// <summary>
    ///     In equality operator.
    ///
    ///     We are stateful, therefore always unequal. We'll let
    ///     the equality operator handle that for us.
    /// </summary>
    ///
    /// <param name="other">The other allocator</param>
    bool operator != (const ShmAllocator & other) const
    {
        return !( *this == other );
    }

    /// <summary>
    ///     Constructs a
    /// </summary>
    ///
    /// <param name="p">[in,out] If non-null, the p.</param>
    /// <param name="t">The t.</param>
    void construct(T *const p, const T & t) const
    {
        void *const pv = static_cast<void *>( p );

        new (pv) T(t);
    }

    /// <summary>
    ///     Destroys the given p.
    /// </summary>
    ///
    /// <param name="p">[in,out] If non-null, the p.</param>
    void destroy(T *const p) const;                         // Defined below.

    /// <summary>
    ///     Equality operator.
    ///
    ///     Returns true if and only if storage allocated from
    ///     *this can be deallocated from other, and vice versa.
    ///     Since we are stateful (we have a map of pointers to
    ///     handles), we always return FALSE.
    /// </summary>
    ///
    /// <param name="other">The other allocator.</param>
    ///
    /// <returns>
    ///     true if the parameters are considered equivalent.
    /// </returns>
    bool operator == (const ShmAllocator & other) const
    {
        return false;
    }

    // Default constructor, copy constructor, rebinding constructor, and destructor.

    /// <summary>
    ///     Initializes a new instance of the ShmAllocator
    ///     class.
    /// </summary>
    ShmAllocator( ) { }

    /// <summary>
    ///     Initializes a new instance of the ShmAllocator class.
    /// </summary>
    ///
    /// <param name="">The.</param>
    ShmAllocator(const ShmAllocator &) { }

    /// <summary>
    ///     Shm allocator.
    /// </summary>
    ///
    /// <param name="">The.</param>
    ///
    /// <returns>
    ///     .
    /// </returns>
    template<typename U> ShmAllocator(const ShmAllocator<U> &) { }

    /// <summary>
    ///     Finalizes an instance of the ShmAllocator class.
    ///     Release any dangling references Further use of
    ///     allocate() pointers should fail spectacularly.
    /// </summary>
    ~ShmAllocator( )
    {
        for (HandleMap::iterator it= mHandles.begin( ); it != mHandles.end( ); ++it )
        {
            unmapView((T*)it->first);
            closeHandle((T*)it->first);
        }
        mHandles.clear();
    }

    /// <summary>
    ///     Allocate a buffer
    ///
    ///     The return value of allocate(0) is unspecified.
    ///     ShmAllocator returns NULL.
    /// </summary>
    ///
    /// <exception cref="std::length_error">Thrown when a length error error condition occurs.
    ///     All allocators should contain an integer overflow
    ///     check. The Standardization Committee recommends that
    ///     std::length_error be thrown in the case of integer
    ///     overflow.</exception>
    /// <exception cref="std::bad_alloc">Thrown when a bad
    ///     allocate error condition occurs.</exception>
    ///
    /// <param name="n">The number of elements of type T to be
    ///     allocated.</param>
    ///
    /// <returns>
    ///     Pointer to the newly allocated buffer.
    /// </returns>
    T *allocate(const size_t n, const char* name)
    {
        if ( n == 0 )
        {
            return NULL;
        }

        if ( n > max_size( ) )
        {
            throw std::length_error("ShmAllocator<T>::allocate() - Integer overflow.");
        }

        if (name == 0 || strlen(name)==0)
        {
            throw std::length_error("ShmAllocator<T>::allocate() - null or bad name.");
        }

        // ShmAllocator wraps CreateFile
        int size = n * sizeof( T );

        HANDLE handle = CreateFileMappingA(
            INVALID_HANDLE_VALUE,                              // use paging file
            NULL,                                              // default security
            PAGE_READWRITE,                                    // read/write access
            0,                                                 // maximum object size (high-order DWORD)
            size,                                              // maximum object size (low-order DWORD)
            name);                                             // name of mapping object

        auto lastErr = GetLastError();

        // Allocators should throw std::bad_alloc in the case of memory allocation failure.
        if ( handle == 0 )
        {
            std::ostringstream msg;
            msg << "Error creating file mapping object: " << hex(lastErr);
            throw std::bad_alloc(msg.str().c_str() );
        }

        bool firstOnScene = (lastErr != ERROR_ALREADY_EXISTS);

        void *const pv = MapViewOfFile(handle,                             // handle to map object
                                        FILE_MAP_ALL_ACCESS,                  // read/write permission
                                        0,
                                        0,
                                        size);

        // Allocators should throw std::bad_alloc in the case of memory allocation failure.
        if ( !pv )
        {
            CloseHandle(handle);
            std::ostringstream msg;
            msg << "Error creating file mapping object: " << hex(GetLastError());
            throw std::bad_alloc(msg.str().c_str() );
        }

        mHandles[(uintptr_t)pv] = handle;

        if (firstOnScene)   //we'll set the memory to zero 
        {
            memset(pv, 0, size);
        }

        return static_cast<T *>( pv );
    }

    /// <summary>
    ///     Deallocates a buffer allocated by allocate(). Null
    ///     is ignored without an error.
    /// </summary>
    ///
    /// <param name="p">[in,out] If non-null, the p.</param>
    /// <param name="n">The count - we ignore it</param>
    void deallocate(T *const p, size_t n = 0) 
    {
        if (mHandles.find((uintptr_t)p) == mHandles.end())  //we don't own this pointer
        {
            std::ostringstream msg;
            msg << "Error in deallocate(): Invalid pointer - we don't own it - we can't delete it!";
            throw std::exception(msg.str().c_str() );
        }

        unmapView(p);
        closeHandle(p);
        mHandles.erase((uintptr_t)p);

    }

    /// <summary>
    ///     Allocate with hint.
    ///
    ///     We ignore the hint.
    /// </summary>
    ///
    /// <param name="n">The count of items to allocate for</param>
    /// <param name="">The hint</param>
    ///
    /// <returns>
    ///     null if it fails, else.
    /// </returns>
    //template<typename U>
    //T *allocate(const size_t n, const U * /* const hint */) const
    //{
    //  return allocate(n);
    //}

private:

    /// <summary>
    ///     Unmap view.
    /// </summary>
    ///
    /// <exception cref="std::exception">Thrown when an exception
    ///     error condition occurs.</exception>
    ///
    /// <param name="p">[in,out] If non-null, the p.</param>
    void unmapView(T*const p)
    {
        if (!UnmapViewOfFile(p))
        {
            std::ostringstream msg;
            msg << "Error deallocating buffer: " << hex(GetLastError());
            throw std::exception(msg.str().c_str() );
        }
    }

    /// <summary>
    ///     Closes a handle.
    /// </summary>
    ///
    /// <exception cref="std::exception">Thrown when an exception
    ///     error condition occurs.</exception>
    ///
    /// <param name="p">[in,out] If non-null, the p.</param>
    void closeHandle(T* const p)
    {
        if (!CloseHandle(mHandles[(uintptr_t)p]))
        {
            std::ostringstream msg;
            msg << "Error deallocating buffer: " << hex(GetLastError());
            throw std::exception(msg.str().c_str() );
        }
    }

    /// <summary>
    ///     Assignment operator.
    ///
    ///     Allocators are not required to be assignable, so all
    ///     allocators should have a private unimplemented
    ///     assignment operator. Note that this will trigger the
    ///     off-by-default (enabled under /Wall) warning C4626
    ///     "assignment operator could not be generated because
    ///     a base class assignment operator is inaccessible"
    ///     within the STL headers, but that warning is useless.
    /// </summary>
    ///
    /// <param name="">The other object</param>
    ///
    /// <returns>
    ///     A shallow copy of this object.
    /// </returns>
    ShmAllocator & operator = (const ShmAllocator &);

    /// <summary> Map from allocate() T* to the underlying HANDLE </summary>
    HandleMap mHandles;

};

/// A compiler bug causes it to believe that p->~T() doesn't reference p.

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4100)         // unreferenced formal parameter
#endif

/// <summary>
///     Destroys the given p.
///
///     The definition of destroy() must
///     be the same for all allocators.
/// </summary>
///
/// <typeparam name="T">Generic type parameter.</typeparam>
/// <param name="p">[in,out] If non-null, the T *const to
///     destroy.</param>
template<typename T>
void ShmAllocator<T>::destroy(T *const p) const
{
    p->~T( );
}


#ifdef _MSC_VER
#pragma warning(pop)
#endif

