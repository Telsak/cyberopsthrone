import json
import argparse
from datetime import datetime

# Sample JSON data as a string
json_data = '''
{
  "assignment": [
    {
      "timestamp": 1714067160.91234,
      "time_used": "85",
      "username": "jasm0002",
      "socket": "151.177.146.56:35792"
    },
    {
      "timestamp": 1714816884.9948666,
      "time_used": "25",
      "username": "siol0003",
      "socket": "94.191.136.241:13898"
    },
    {
      "timestamp": 1714066160.91234,
      "time_used": "55",
      "username": "jasm0002",
      "socket": "151.177.146.57:35792"
    }
  ]
}
'''

parser = argparse.ArgumentParser(description="Process a JSON file to find earliest log entries for each user.")
parser.add_argument("filename", type=str, help="Filename of the JSON file to process")
args = parser.parse_args()

def load_json_data(filepath):
    with open(filepath, "r") as file:
        return json.load(file)

data = load_json_data(args.filename)

entries = {}

for entry in data["assignment"]:
    username = entry["username"]
    if username not in entries or entry["timestamp"] < entries[username]["timestamp"]:
        entries[username] = entry

sorted_entries = sorted(entries.values(), key=lambda x: x["timestamp"])

output = []
for entry in sorted_entries:
    date_time = datetime.utcfromtimestamp(entry["timestamp"]).strftime('%Y-%m-%d %H:%M:%S')
    output.append(f'{entry["username"]} - {date_time} - {entry["socket"]}')

for entry in output:
    print(entry)
