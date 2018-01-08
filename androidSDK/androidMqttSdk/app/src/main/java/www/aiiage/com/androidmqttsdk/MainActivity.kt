package www.aiiage.com.androidmqttsdk

import android.support.v7.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import com.aliyun.alink.linksdk.channel.core.base.AError
import com.aliyun.alink.linksdk.channel.core.persistent.IOnSubscribeListener
import com.aliyun.alink.linksdk.channel.core.persistent.PersistentNet
import com.aliyun.alink.linksdk.channel.core.persistent.mqtt.MqttConfigure
import com.aliyun.alink.linksdk.channel.core.persistent.mqtt.MqttInitParams
import com.aliyun.alink.linksdk.tools.ALog
import com.aliyun.alink.linksdk.channel.core.persistent.event.IConnectionStateListener
import com.aliyun.alink.linksdk.channel.core.persistent.event.IOnPushListener
import com.aliyun.alink.linksdk.channel.core.persistent.event.PersistentEventDispatcher
import com.aliyun.alink.linksdk.channel.core.base.ARequest
import com.aliyun.alink.linksdk.channel.core.base.AResponse
import com.aliyun.alink.linksdk.channel.core.base.IOnCallListener
import com.aliyun.alink.linksdk.channel.core.persistent.mqtt.request.MqttPublishRequest
import com.google.gson.Gson
import kotlinx.android.synthetic.main.activity_main.*


class MainActivity : AppCompatActivity() {

    // 产品key
    val productKey = ""

    // 设备名称  唯一
    val deviceName = ""

    //deviceSecret
    val  deviceSecret = ""

    //Host
    val  tcpHost = "ssl://${productKey}.iot-as-mqtt.cn-shanghai.aliyuncs.com:1883"

    //需要订阅的主题
    val topic = "/"+productKey+"/"+deviceName+"/"+"map"



    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

         initListen()
    }

    private fun initListen() {
        btn_tcp.setOnClickListener {
            Log.w(this.toString(),"点击了连接按钮")
            SDKConnect()
        }
    }


    /**
     *  Tcp 直连
     */
    private fun SDKConnect(){

        //打开日志
        ALog.setLevel(ALog.LEVEL_DEBUG)

        //环境配置
        MqttConfigure.mqttHost = tcpHost


        //SDK 初始化
        val initParams = MqttInitParams(productKey,deviceName,deviceSecret)
        PersistentNet.getInstance().init(applicationContext,initParams)

        //添加通道状态变化监听
        PersistentEventDispatcher.getInstance().registerOnTunnelStateListener(object: IConnectionStateListener {
            override fun onConnected(){
                    PersistentNet.getInstance().subscribe(topic,object:IOnSubscribeListener {
                        override fun onSuccess(p0: String?) {
                            print("订阅成功")
                        }

                        override fun needUISafety(): Boolean {
                            return false
                        }

                        override fun onFailed(p0: String?, p1: AError?) {
                            print(p0)
                        }

                    })
            }

            override fun onConnectFail(p0: String?) {
                print("连接失败")
            }

            override fun onDisconnect() {
                print("取消连接")
            }
        },true)



        PersistentEventDispatcher.getInstance().registerOnPushListener(object:IOnPushListener{
            override fun onCommand(p0: String?, p1: String?) {

                val gson = Gson()
                val list = gson.fromJson(p1,MapBean::class.java)

                val mapstr = list.map

                Log.e(this.toString(), mapstr!!.length.toString())
            }

            override fun shouldHandle(p0: String?): Boolean {
                return true
            }
        },true)

    }


     private  fun sendMsg(msg:String){
         val publishRequest = MqttPublishRequest()
         publishRequest.isRPC = false
         publishRequest.topic = topic
         publishRequest.payloadObj = msg

         PersistentNet.getInstance().asyncSend(publishRequest, object : IOnCallListener {

             override fun onSuccess(request: ARequest, response: AResponse) {
                 print("发送数据成功")
             }

             override fun onFailed(request: ARequest, error: AError) {
                 print("发送失败")
             }

             override fun needUISafety(): Boolean {
                 return true
             }
         })
     }
}

