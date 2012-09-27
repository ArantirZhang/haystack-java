//
// Copyright (c) 2011, SkyFoundry, LLC
// Licensed under the Academic Free License version 3.0
//
// History:
//   07 Jun 2011  Brian Frank  My birthday!
//
package haystack;

/**
 * UnknownNameException is thrown when attempting to perform
 * a checked lookup by name for a tag/col not present.
 */
public class UnknownNameException extends RuntimeException
{

  /** Constructor with message */
  public UnknownNameException(String msg)
  {
    super(msg);
  }

}