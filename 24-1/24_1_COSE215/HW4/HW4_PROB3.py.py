import re

phone_number = r'\d{3}-\d{4}-\d{4}'
card_number = r'\d{4}-\d{4}-\d{4}-\d{4}'

with open('Secret_disk.txt', 'r') as file:
    content = file.read()

list_phone = re.findall(phone_number, content)
list_card = re.findall(card_number, content)

valid_phone_numbers = []

for phone in list_phone:
    if not any(phone in card for card in list_card):
        valid_phone_numbers.append(phone)

print("Phone Numbers")
for phone in valid_phone_numbers:
    print(phone)

print()

print("Card Numbers")
for card in list_card:
    print(card)
