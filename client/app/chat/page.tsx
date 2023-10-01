"use client"
import Cookies from "js-cookie"
import { useRouter } from "next/navigation"
import axios from "axios"
import { useEffect, useState } from "react"

interface IMsg {
  ID: string
  Text: string
  Timestamp: string
  UserID: string
}

export default function Chat() {
  const router = useRouter()
  const socket = new WebSocket('ws://localhost:8080/ws');

  const [userId, setUserId] = useState(-1)
  const [msgs, setMsgs] = useState<IMsg[]>([])
  const [text, setText] = useState("")

  const checkIt = async () => {
    const token = Cookies.get("token")
    if (!token) return false
    try {
      const response = await axios.get("http://localhost:8080/messages", { headers: { Authorization: token } })
      if(response.data.msg) {

        setMsgs(response.data.msg)
        // ms = response.data.msg
      }
      setUserId(prev => prev = response.data.userId)
      // console.log(response)
    } catch (err) {
      router.push("/")
    }
  }


  useEffect(() => {
    // let ms:any[] = []
    if (!checkIt()) router.push("/")
    socket.onopen = (event)=>{
      console.log('WebSocket connection opened:', event);
    }



 socket.onmessage = (event:any) => {
    // console.log(event)
    // const temp = msgs
    const d = JSON.parse(event.data)
    // const m = msgs
    console.log(msgs)
    // console.log(ms)
    // m.push(d)
    // setMsgs([...ms,d])
    // console.log(m)
    // addToMsgs(d)
    setMsgs((prevMsgs) => [...prevMsgs, d]);

  } 


  }, [])

  const addToMsgs = (m: any) => {
    setMsgs([...msgs,m])
  }

  const handleOnSendMsg = () => {
    // console.log(userId)
    socket.send(JSON.stringify({ text, userID: userId }));
  }


  return (
    <div className="flex bg-white h-full flex-col p-4">
      <div className="flex-1 flex flex-col space-y-2 bg-purple-20">
        {msgs.map((m,i) => (
          <div key={i} className={`${Number(m.UserID) === userId ? "bg-blue-100 self-end" : "bg-gray-200"} py-2 px-4 rounded-lg max-w-xs`}>
            <p className="text-sm">{m.Text}</p>
          </div>
        ))}
      </div>
      <div className="flex items-center mt-4 sticky bottom-0">
        <input value={text} onChange={e => setText(e.target.value)} type="text" placeholder="Type your message..." className="w-full px-4 py-2 rounded-lg border focus:outline-none focus:border-blue-500" />
        <button onClick={handleOnSendMsg} className="bg-blue-500 text-white px-4 py-2 rounded-lg ml-2">Send</button>
      </div>
    </div>
  )
}
