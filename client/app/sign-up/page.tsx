"use client"
import { useState } from "react"
import axios from "axios"
import {useRouter} from "next/navigation"

interface ISignUpData {
  username: string
  password: string
}

export default function SignUp() {
  const router =  useRouter()
  const [signUpData, setSignUpData] = useState<ISignUpData>({ username: "", password: "" })

  const handleOnPressSignUp = async () => {
    if (!signUpData.password || !signUpData.username) {
      alert("input data is not complete")
      return
    }

    try {
      const data = await axios.post("http://localhost:8080/register", signUpData)
      console.log(data)
      if(data.status === 201)  router.push("/sign-in")
    } catch (err) {
      console.log(err)
    }
  }

  return (
    <div className="flex justify-center ">
      <div className="border flex flex-col mt-[200px] rounded-lg p-2">
        <label htmlFor="">Username</label>
        <input type="text" className="border" value={signUpData.username} onChange={e => setSignUpData({...signUpData, username: e.target.value})} />
        <label htmlFor="">Password</label>
        <input type="text" className="border" value={signUpData.password} onChange={e => setSignUpData({...signUpData, password: e.target.value})} />
        <button onClick={handleOnPressSignUp} className="bg-gray-200 mt-4 rounded-lg py-2">Sign up</button>
      </div>
    </div>
  )
}
