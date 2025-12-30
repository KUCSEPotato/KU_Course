module digit_to_7seg (
   input [3:0] digit,    
   output [6:0] _7seg   
);
   assign _7seg[0] = ((~digit[3])&(~digit[2])&(~digit[1])&digit[0]) | (digit[2]&(~digit[1])&(~digit[0])) | (digit[3]&(~digit[2])&digit[1]&digit[0]) | (digit[3]&digit[2]&(~digit[1]));
   // Calculate the first bit (a) of the 7-segment display.

   assign _7seg[1] =(digit[3]&digit[1]&digit[0]) | (digit[3]&digit[2]&(~digit[0])) | (digit[2]&digit[1]&(~digit[0])) | ((~digit[3])&digit[2]&(~digit[1])&digit[0]);
   // Calculate the second bit (b) of the 7-segment display.

   assign _7seg[2]= (digit[3]&digit[2]&digit[1]) | (digit[3]&digit[2]&(~digit[0])) | ((~digit[3])&(~digit[2])&digit[1]&(~digit[0]));
   // Calculate the third bit (c) of the 7-segment display.

   assign _7seg[3] = (digit[2]&digit[1]&digit[0]) | ((~digit[3])&(~digit[2])&(~digit[1])&digit[0]) | ((~digit[3])&digit[2]&(~digit[1])&(~digit[0])) | (digit[3]&(~digit[2])&digit[1]&(~digit[0]));
   // Calculate the fourth bit (d) of the 7-segment display.

   assign _7seg[4] = ((~digit[3])&digit[0]) | ((~digit[3])&digit[2]&(~digit[1])) | ((~digit[2])&(~digit[1])&digit[0]);
   // Calculate the fifth bit (e) of the 7-segment display.

   assign _7seg[5] = (digit[3]&digit[2]&(~digit[1])) | ((~digit[3])&digit[1]&digit[0]) | ((~digit[3])&(~digit[2])&digit[0]) | ((~digit[3])&(~digit[2])&digit[1]);
   // Calculate the sixth bit (f) of the 7-segment display.

   assign _7seg[6] = ((~digit[3])&(~digit[2])&(~digit[1])) | ((~digit[3])&digit[2]&digit[1]&digit[0]);
   // Calculate the seventh bit (g) of the 7-segment display.
   
endmodule
