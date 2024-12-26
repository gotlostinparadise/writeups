# HackTheBox: Diogenes' Rage

## Challenge Information

**Challenge Description:** Having missed the flight as you walk down the street, a wild vending machine appears in your way. You check your pocket and there it is, yet another half torn voucher coupon to feed to the consumerism. You start wondering why should you buy things that you don't like with the money you don't have for the people you don't like. You're Jack's raging bile duct.

**Challenge Points:** 20 points

**Challenge Solves:** 1700

**Challenge Files:** https://app.hackthebox.com/challenges/diogenes-rage

## Initial Analysis

We can see a simple web application that appears to be a virtual vending machine interface. The interface includes a grid of options labeled with letters (A, B, C) and numbers (1 to 9), similar to the layout of a physical vending machine. Each option corresponds to a specific price, ranging from $0.15 to $13.37. The text "HTB Coupons Accepted! Insert coins below!" suggests that the application accepts some form of coupon or token for transactions.

Application source code was provided on the page of the challenge.
![looking at the source code](../../../assets/htb/diogenes-rage/burp_requests_review.gif)

I launched Burp Suite and started my investigation.

![looking at the webapp](../../../assets/htb/diogenes-rage/web_app_overview.gif)
![looking at the requests](../../../assets/htb/diogenes-rage/burp_requests_review.gif)

There were only 3 endpoints that are interesting to us:

<details>
    <summary>
        <b>Reset session - /api/reset</b>
    </summary>

    router.get("/api/reset", async (req, res) => {
        res.clearCookie("session");
        res.send(response("Insert coins below!"));
    });

</details>

<details>
    <summary>
        <b>Purchase an item - /api/purchase</b>
    </summary>

    router.post("/api/purchase", AuthMiddleware, async (req, res) => {
        return db.getUser(req.data.username).then(async (user) => {
            if (user === undefined) {
            await db.registerUser(req.data.username);
            user = { username: req.data.username, balance: 0.0, coupons: "" };
            }
            const { item } = req.body;
            if (item) {
            return db.getProduct(item).then((product) => {
                if (product == undefined)
                return res.send(response("Invalid item code supplied!"));
                if (product.price <= user.balance) {
                newBalance = parseFloat(user.balance - product.price).toFixed(2);
                return db.setBalance(req.data.username, newBalance).then(() => {
                    if (product.item_name == "C8")
                    return res.json({
                        flag: fs.readFileSync("/app/flag").toString(),
                        message: `Thank you for your order! $${newBalance} coupon credits left!`,
                    });
                    res.send(
                    response(
                        `Thank you for your order! $${newBalance} coupon credits left!`
                    )
                    );
                });
                }
                return res.status(403).send(response("Insufficient balance!"));
            });
            }
            return res.status(401).send(response("Missing required parameters!"));
        });
    });

</details>

<details>
    <summary>
        <b>Apply coupon - /api/coupons/apply</b>
    </summary>
    
    router.post("/api/coupons/apply", AuthMiddleware, async (req, res) => {
        return db.getUser(req.data.username).then(async (user) => {
            if (user === undefined) {
                await db.registerUser(req.data.username);
                user = { username: req.data.username, balance: 0.0, coupons: "" };
            }
        const { coupon_code } = req.body;
        if (coupon_code) {
            if (user.coupons.includes(coupon_code)) {
            return res
                .status(401)
                .send(response("This coupon is already redeemed!"));
            }
            return db.getCouponValue(coupon_code).then((coupon) => {
            if (coupon) {
                return db
                .addBalance(user.username, coupon.value)
                .then(() => {
                    db.setCoupon(user.username, coupon_code).then(() =>
                    res.send(
                        response(
                        `$${coupon.value} coupon redeemed successfully! Please select an item for order.`
                        )
                    )
                    );
                })
                .catch(() => res.send(response("Failed to redeem the coupon!")));
            }
            res.send(response("No such coupon exists!"));
            });
        }
        return res.status(401).send(response("Missing required parameters!"));
        });
    });
</details>

---

## Detailed Writeup

[This section should provide a detailed step-by-step walkthrough of how you approached and solved the challenge. It should be thorough and include any commands used, code snippets, screenshots, etc.]

### Step 1: Analyze the authentication mechanism

The authentication is tied to session cookies set on initial visits. Specifically, the AuthMiddleware middleware checks the request for a session cookie. It then verifies there is a corresponding user session with that ID in the SQLite database.

To bypass this authentication, we can call the /api/reset endpoint. This resets the session cookie by clearing it from the response. Now when we make further requests, there will be no session cookie so the backend cannot verify the session. This allows us to make requests as an unauthenticated user and bypass the intended login flow.

I confirmed this by making requests in Burp Suite. A request to /api/reset returns a 200 OK response that removes the session cookie. Subsequent requests no longer contain the session cookie, and the API endpoints allow access without authentication.

### Step 2: Fuzz for coupon codes

There are no obvious coupon codes hardcoded in the source code or responses. To find valid coupon codes, we need to fuzz/brute force the format since codes seem to follow the structure HTB_<digits>.

I set up a Burp Intruder attack to brute force numeric suffixes from 0 to 1000. This sends requests with payload positions like HTB_0, HTB_1, etc.

The only valid coupon code found was HTB_100. Applying this code returns a 200 OK response and adds 1 credit to the account balance. All other suffixes returned a "No such coupon exists" error.
![](../../../assets/htb/diogenes-rage/intruder.png)

I also tried fuzzing different prefixes besides "HTB_" but did not find any valid formats. After manually testing prefixes like "COUPON", it seems the application only accepts codes starting with "HTB_".

### Step 3: Exploit race condition to multiply credits

To purchase the C8 item and get the flag, we need a balance of over 13 credits. However, we only have 1 valid coupon code that gives 1 credit.

The key insight is that we can exploit an asynchronous race condition in the coupon redemption code to multiply our credits. Because the application uses async/await, the voucher verification steps run in parallel.

This allows us to rapidly send multiple parallel requests to redeem the same HTB_100 code before the application has updated the database to disable it. Each request verifies the coupon is valid and adds 1 credit, so 15 parallel requests gives 15 credits from a single coupon code.

In this Python implementation, the asyncio library is utilized to efficiently manage asynchronous HTTP requests. The process involves:

- Initializing an asynchronous HTTP client session.
- Defining a `buy_product` function to make a POST request to the /api/purchase endpoint to attempt purchasing the C8 item. The function accepts an optional `cookies` parameter for session management and returns the response cookies.
- Defining a `redeem_coupon` function to send POST requests to the /api/coupons/apply endpoint, attempting to redeem the HTB_100 coupon. This function also takes `cookies` as a parameter to maintain session state.
- A `redeem_many_coupons` function is set up to create and manage multiple asyncio tasks, each calling `redeem_coupon`. It uses asyncio.gather to await all requests and calculates the total number of successful redemptions.
- The main `perform_actions` function orchestrates the process by first attempting a product purchase, then repeatedly redeeming coupons until at least 13 successful redemptions are achieved, and finally attempting to purchase the C8 item again with the accumulated credits.
- The `main` function sets up necessary parameters and calls `perform_actions` within the asyncio event loop.

![](../../../assets/htb/diogenes-rage/code.png)

The script gave ~15 successful redemptions in one batch, providing enough credits to buy the C8 item. The response contained the flag **HTB{r4c3_w3b_------------------}**.

The key was abusing the race condition created by async code and rapid parallel requests to multiply the value of a single coupon code.

### Conclusion

This challenge demonstrated how a logic flaw in implementing asynchronous voucher redemption allowed multiplying credits from one coupon. By combining coupon code fuzzing with an asyncio-based script to exploit the race, we could escalate 1 credit to 15+ and retrieve the flag by purchasing the target C8 item.


## References

- [HackTricks](https://book.hacktricks.xyz/pentesting-web/race-condition)
