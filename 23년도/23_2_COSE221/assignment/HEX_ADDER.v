module HEX_ADDER(
   input [3:0] a,
   input [3:0] b,
   input cin,
       output [3:0]sout,
       output carry_out
);

   
    _4bit_FA _4FA0(.a(a), .b(b), .cin(cin), .s(sout), .cout(carry_out));
   // Instantiates a 4-bit full adder module to perform the addition.
   // Inputs a and b are the operands.
   // Input cin is the carry-in to the addition.
   // Output sout represents the sum of a and b.
   // Output carry_out represents the carry-out from the addition.


endmodule