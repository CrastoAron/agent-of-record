import React from "react";
import ChatInterface from "./ChatInterface";

/**
 * ClientSigning now serves as the entry point to the conversational Agent-of-Record
 * interface, where each user request and agent execution is treated as a conversation action.
 */
export default function ClientSigning() {
  return <ChatInterface />;
}
