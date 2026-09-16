import sys


def calculate_crc16_ccitt(data: str) -> str:
"""Calculates CRC16-CCITT (False / 0xFFFF initial value) checksum for EMVCo strings."""
crc = 0xFFFF
polynomial = 0x1021

for byte in data.encode("utf-8"):
crc ^= byte << 8
for _ in range(8):
if crc & 0x8000:
crc = ((crc << 1) ^ polynomial) & 0xFFFF
else:
crc = (crc << 1) & 0xFFFF

return f"{crc:04X}"


def parse_emvco_tlv(payload: str):
"""Parses EMVCo TLV string into a structured dictionary."""
i = 0
parsed = {}

while i < len(payload):
if i + 4 > len(payload):
raise ValueError(f"Malformed string at position {i}: incomplete TL header.")

tag = payload[i : i + 2]
try:
length = int(payload[i + 2 : i + 4])
except ValueError:
raise ValueError(
f"Invalid length value '{payload[i+2:i+4]}' at position {i+2}."
)

value_start = i + 4
value_end = value_start + length

if value_end > len(payload):
raise ValueError(
f"Tag {tag} specifies length {length}, but remaining payload length is short."
)

value = payload[value_start:value_end]
parsed[tag] = value
i = value_end

return parsed


# EMVCo Standard Tag Names
EMVCO_TAG_DESCRIPTIONS = {
"00": "Payload Format Indicator",
"01": "Point of Initiation Method (11: Static, 12: Dynamic)",
"52": "Merchant Category Code (MCC)",
"53": "Transaction Currency Code (ISO 4217)",
"54": "Transaction Amount",
"55": "Tip or Convenience Indicator",
"56": "Value of Convenience Fee Fixed",
"57": "Value of Convenience Fee Percentage",
"58": "Country Code (ISO 3166-1 alpha-2)",
"59": "Merchant Name",
"60": "Merchant City",
"61": "Postal Code",
"62": "Additional Data Field Template",
"63": "CRC Checksum",
}


def analyze_emvco_qr(payload: str):
"""Validates CRC and prints standard EMVCo specifications."""
payload = payload.strip()

if not payload:
print("Error: Input payload is empty.")
return

# Check for CRC Tag 63 at the end
if not payload.endswith("6304") and "6304" not in payload[-8:]:
print(
"⚠️ Warning: String does not end with standard CRC Tag '6304'. Attempting parsing...\n"
)
else:
# Validate Checksum
data_to_check = payload[:-4]
expected_crc = payload[-4:].upper()
calculated_crc = calculate_crc16_ccitt(data_to_check)

print("-" * 50)
if expected_crc == calculated_crc:
print(f"✅ CRC Validation Passed! (CRC: {calculated_crc})")
else:
print(
f"❌ CRC Validation Failed! Expected: {expected_crc}, Calculated: {calculated_crc}"
)
print("-" * 50)

try:
tlv_dict = parse_emvco_tlv(payload)
except ValueError as err:
print(f"Parsing Error: {err}")
return

print("\nParsed EMVCo Fields:")
print(f"{'Tag':<5} | {'Length':<6} | {'Standard Name':<35} | {'Value'}")
print("-" * 75)

for tag, value in tlv_dict.items():
if tag.isdigit() and 2 <= int(tag) <= 51:
desc = f"Merchant Account Info ({tag})"
elif tag.isdigit() and 65 <= int(tag) <= 79:
desc = f"RFU for EMVCo ({tag})"
elif tag.isdigit() and 80 <= int(tag) <= 99:
desc = f"Unreserved Templates ({tag})"
else:
desc = EMVCO_TAG_DESCRIPTIONS.get(tag, "Custom / Sub-Tag")

print(f"{tag:<5} | {len(value):<6} | {desc:<35} | {value}")


if __name__ == "__main__":
print("=== EMVCo QR Code Decoder & Validator ===")
user_input = input("Paste your decoded QR string here: ")
analyze_emvco_qr(user_input)
