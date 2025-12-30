///////////////////////Top module/////////////////////////////////////
module top_HEX_ADDER( 
   input [15:0] SW,               
   output [6:0] HEX7,HEX6, HEX5,HEX4, HEX2,HEX1,HEX0 
);
   
wire [3:0] input0, input1, input2, input3; 

wire [3:0] result1, result2;  

assign input0 = SW[15:12];  
assign input1 = SW[11:8]; 
assign input2 = SW[7:4];  
assign input3 = SW[3:0];   

wire carry_in;               // Carry in
assign carry_in = 1'b0;      // Set carry_in  0

wire carry_out;              // Carry Out 
wire carry_out2;             // Carry Out2 

// Create two hex_adder instances
HEX_ADDER hex_adder0 (input1, input3, carry_in, result2, carry_out);
HEX_ADDER hex_adder1 (input0, input2, carry_out, result1, carry_out2);

digit_to_7seg hex7(input0, HEX7); // Convert input0 to 7-segment display for HEX7
digit_to_7seg hex6(input1, HEX6); // Convert input1 to 7-segment display for HEX6
digit_to_7seg hex5(input2, HEX5); // Convert input2 to 7-segment display for HEX5
digit_to_7seg hex4(input3, HEX4); // Convert input3 to 7-segment display for HEX4

assign HEX2 = (carry_out2 == 1'b1)? 7'b111_1001 : 7'b111_1111; // Set HEX2 based on the value of carry_out2
digit_to_7seg hex1(result1, HEX1); // Convert result1 to 7-segment display for HEX1
digit_to_7seg hex0(result2, HEX0); // Convert result2 to 7-segment display for HEX0

endmodule
///////////////////////End of top module ////////////////////////////////
