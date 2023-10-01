"use client"
import { useState } from "react"
import axios from "axios"
import {useRouter} from "next/navigation"
import Cookies from "js-cookie"

interface ISignInData {
  username: string
  password: string
}

export default function SignIn() {
  const router =  useRouter()
  // const cookei = Cookies()
  const [signInData, setSignInData] = useState<ISignInData>({ username: "", password: "" })

  const handleOnPressSignIn = async () => {
    if (!signInData.password || !signInData.username) {
      alert("input data is not complete")
      return
    }

    try {
      const response = await axios.post("http://localhost:8080/login", signInData)
      console.log(response)

      if(response.status === 200) {
        Cookies.set("token", response.data.token)
        router.push("/chat")
      }
    } catch (err) {
      console.log(err)
    }
  }

  return (
    <div className="flex justify-center ">
      <div className="border flex flex-col mt-[200px] rounded-lg p-2">
        <label htmlFor="">Username</label>
        <input type="text" className="border" value={signInData.username} onChange={e => setSignInData({...signInData, username: e.target.value})} />
        <label htmlFor="">Password</label>
        <input type="text" className="border" value={signInData.password} onChange={e => setSignInData({...signInData, password: e.target.value})} />
        <button onClick={handleOnPressSignIn} className="bg-gray-200 mt-4 rounded-lg py-2">Sign In</button>
      </div>
    </div>
  )
}
