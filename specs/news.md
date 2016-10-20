# Client to news-server protocol
## Transport: SSL
## Authentication
Immediately after the connection is setup the client sends the AUTH command to authenticate.
```python
>> AUTH: USERNAME_BASE64_STRING PWD_IN_BASE64_STRING
<< AUTH: OK
>> SET INFO: ACCOUNT geert@mobicage.com
>> SET INFO: APP be-loc
>> SET INFO: FRIENDS ["geert@mobicage.com","info@latapacanaria.be"]
```
Or
```python
<< AUTH: ERROR
<< <EOF>
```

## News
### Client announcing news read
```python
>> NEWS READ: 78979
<< ACK NEWS READ: 78979
```
### Server announcing news read update
```python
<< NEWS READ UPDATE: 78979 125 78980 12 47856 5632
```
### Client requesting news stats
```python
>> NEWS STATS: 78979 78980 47856
<< NEWS STATS: {"78979": {"reach" :125, "users_that_rogered": ["geert@mobicage.com"]},
                "78980": {"reach" :12, "users_that_rogered": []},
                "47856": {"reach" :5632, "users_that_rogered": []}}
```
### Client announcing news roger
```python
>> NEWS ROGER: 78979
<< ACK NEWS ROGER: 78979
```
### Server announcing news roger update
```python
<< NEWS ROGER UPDATE: 78979 geert@mobicage.com
```
#### Server announcing news
```python
<< NEWS PUSH: {id=4645313, title=’Ongeval in de linde…’, ...}
```
