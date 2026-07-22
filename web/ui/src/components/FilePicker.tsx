import { useId } from "react";

type Props = {
  accept?: string;
  required?: boolean;
  file: File | null;
  onChange: (file: File | null) => void;
  label?: string;
};

export default function FilePicker({ accept, required, file, onChange, label = "Choose file" }: Props) {
  const id = useId();
  return (
    <div className="file-picker">
      <input
        id={id}
        className="file-picker-input"
        type="file"
        accept={accept}
        required={required}
        onChange={(e) => onChange(e.target.files?.[0] || null)}
      />
      <label htmlFor={id} className="btn file-picker-btn">
        {label}
      </label>
      <span className="file-picker-name" title={file?.name || undefined}>
        {file?.name || "No file chosen"}
      </span>
    </div>
  );
}
