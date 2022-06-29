# mi-client

Yet another XiaoMi IOT service client for node writing by TypeScript.

### Installation

```sh
yarn add mi-client
```

### Usage

```ts
import { MiClient } from 'mi-client'

const client = new MiClient({
  username: '',
  password: '',
})

const resData = await client.request(url, reqData)
```
