import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import legacyMarkup from "./legacy.html?raw";
import "./tailwind.css";
import "../styles.css";

function LanternApp() {
  const [status, setStatus] = useState("Starting Lantern…");
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    import("./legacy.js")
      .then(() => setStatus(""))
      .catch((error) => {
        console.error("Lantern failed to start", error);
        setFailed(true);
        setStatus("Lantern could not start. Refresh this page or restart the server.");
      });
  }, []);

  return (
    <div className="min-h-screen bg-slate-950 font-sans text-slate-100 antialiased selection:bg-teal-300/30">
      {status && (
        <div className="fixed inset-0 z-[100] grid place-items-center bg-slate-950 p-6 text-center">
          <div className="max-w-md rounded-2xl border border-slate-700 bg-slate-900 p-8 shadow-2xl">
            <img className="mx-auto mb-4 h-16 w-16 rounded-xl object-cover" src="/assets/lantern-logo.jpeg" alt="Lantern logo" />
            <p className="text-lg font-semibold text-slate-100">{failed ? "Unable to start" : "Lantern Discovery Assistant"}</p>
            <p className="mt-2 text-sm text-teal-200">{status}</p>
          </div>
        </div>
      )}
      <div dangerouslySetInnerHTML={{ __html: legacyMarkup }} />
    </div>
  );
}

createRoot(document.getElementById("root")).render(<LanternApp />);
