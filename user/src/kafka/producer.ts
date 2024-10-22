import { Kafka, Producer } from 'kafkajs'

const kafka = new Kafka({
  clientId: 'user-service',
  brokers: ['localhost:9092'] // Replace with your Kafka broker addresses
})

const producer: Producer = kafka.producer()

// Connect the producer when your application starts
export const connectProducer = async (): Promise<void> => {
  await producer.connect()
  console.log('Producer connected')
}

interface NewUserEvent {
  eventType: 'NEW_USER_CREATED'
  userId: number
  username: string
  timestamp: string
}

// Function to send a new user event
export const sendNewUserEvent = async (userId: number, username: string): Promise<void> => {
  try {
    const event: NewUserEvent = {
      eventType: 'NEW_USER_CREATED',
      userId,
      username,
      timestamp: new Date().toISOString()
    }

    await producer.send({
      topic: 'user-events',
      messages: [
        {
          key: userId.toString(),
          value: JSON.stringify(event)
        },
      ],
    })
    console.log(`New user event sent for user ${username}`)
  } catch (error) {
    console.error('Error sending new user event:', error)
  }
}

// ... existing code ...
