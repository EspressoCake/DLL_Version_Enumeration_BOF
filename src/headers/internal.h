#pragma once

#include <windows.h>


// Forward declarations
int wcharcmp (const wchar_t *s1, const wchar_t *s2);
size_t __wcslenimplementation (const wchar_t *s);


// Implementations
int wcharcmp(const wchar_t *s1, const wchar_t *s2)
{
  wchar_t c1, c2;
  do
    {
      c1 = *s1++;
      c2 = *s2++;
      if (c2 == L'\0')
        return c1 - c2;
    }
  while (c1 == c2);
  return c1 < c2 ? -1 : 1;
}

size_t __wcslenimplementation (const wchar_t *s)
{
  size_t len = 0;
  while (s[len] != L'\0')
    {
      if (s[++len] == L'\0')
        return len;
      if (s[++len] == L'\0')
        return len;
      if (s[++len] == L'\0')
        return len;
      ++len;
    }
  return len;
}