# Unit testing Kubernetes API interaction with MockClient

The trusted-cluster-operator makes numerous calls to the Kubernetes API in its code.
Alongside integration tests, the operator's functions are also unit tested, which requires mocking the responses of the API.

For a test, responses are sent based on a function that takes the request as well as a counter that is incremented upon each request.
The latter is useful for testing the expected order of requests, plus ensuring all the expected requests were sent.

## Example: `trustee::test_generate_trustee_data_success` in the successful case

In the successul case, `trustee::test_generate_trustee_data_success` performs the following API interactions:


| Count | Action                                                               | Test                                              |
| ----- | -------------------------------------------------------------------- | ------------------------------------------------- |
| 0     | Attempt to get the trustee-data configmap containing kbs-config.toml | HTTP GET, assert failure as the cm doesn't exist. |
| 1     | Create a new ConfigMap called trustee-data.                          | HTTP POST, sends a new ConfigMap default value.   |


A mock endpoint that checks these things can be defined like this:

```rust
let clos = |client| generate_trustee_data(client, Default::default(), &None);
        let server = async |req: Request<_>, ctr| match (ctr, req.method()) {
            (0, &Method::GET) => Err(StatusCode::NOT_FOUND),
            (1, &Method::POST) => Ok(serde_json::to_string(&ConfigMap::default()).unwrap()),
            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
};
```

It can then be used with the `count_check!` macro to also ensure the function sent 2 requests and no fewer. This macro establishes an atomic counter and compares against it; assertions in a Drop implementation would not fire back to the test thread.

```rust
count_check!(2, server, |client| {
            assert!(clos(client).await.is_ok());
});
```

