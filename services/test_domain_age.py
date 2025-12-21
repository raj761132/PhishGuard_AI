from services.final_verdict import final_verdict

urls = [
    "https://gietuerp.xnxx/",
    "rbi.co.in"
]

for url in urls:
    print("\n==============================")
    result = final_verdict(url)

    print("URL:", result["url"])
    print("Final Verdict:", result["final_verdict"])
    print("Risk Level:", result["risk_level"])
    print("Score:", result["score"])

    print("Evidence:")
    for s in result["signals"]:
        print(" -", s)
