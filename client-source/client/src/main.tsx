import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./styles.css";
import { applyCommunityTheme } from "./customization/apply-theme";

applyCommunityTheme();

const root = ReactDOM.createRoot(document.getElementById("root")!);
const showUiPreview = import.meta.env.DEV && new URLSearchParams(window.location.search).has("ui-preview");

if (showUiPreview) {
  void import("./UiPreview").then(({ UiPreview }) => {
    root.render(<UiPreview />);
  });
} else {
  root.render(
    <React.StrictMode>
      <App />
    </React.StrictMode>,
  );
}
