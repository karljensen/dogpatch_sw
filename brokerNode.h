#pragma once

class brokerNode
{
 public:

  enum exchanges {
    nasdaq = 0, // NASDAQ NATIVE (also nasdaq generic catch-all used by nasdaq, bx , psx)
    bx = 1, // NASDAQ BX
    psx = 2, // NASDAQ PSX
    byx = 3, // BATS BYX
    bzx = 4, // BATS BZX
    edga = 5, // BATS EDGA
    edgx = 6, // BATS EDGX
    arca = 7, // NYSE ARCA
    nyse = 8, // NYSE NYSE
    natl = 9, // NYSE NATL
    amer = 10, // NYSE AMER (American)
    chx = 11, // NYSE Chicago
    memx = 12, // Members Exchange
    miax = 13, // MIAX Pearl Equities Exchange (Miami International)
    filler1 = 14, // filler1 
    bats = 15 // bats generic catch-all (used by byx, bzx, edga, edgx)
  };
}; // class brokerNode

