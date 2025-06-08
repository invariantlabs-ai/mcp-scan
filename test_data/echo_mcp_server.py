import sys
import json

def main():
    for line in sys.stdin:
        try:
            req = json.loads(line)
            # 단순히 입력을 그대로 응답
            resp = {
                "id": req.get("id"),
                "result": f"Echo: {req.get('params', '')}"
            }
            print(json.dumps(resp), flush=True)
        except Exception as e:
            print(json.dumps({"error": str(e)}), flush=True)

if __name__ == "__main__":
    main() 