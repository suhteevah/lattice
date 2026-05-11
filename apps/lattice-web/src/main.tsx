/* @refresh reload */
import { render } from "solid-js/web";
import App from "./App";
import "./styles.css";

const root = document.getElementById("root");

if (!root) {
  throw new Error("Root element #root missing from index.html");
}

render(() => <App />, root);
