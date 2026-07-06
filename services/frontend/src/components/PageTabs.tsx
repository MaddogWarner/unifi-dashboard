type Tab = {
  id: string;
  label: string;
};

type Props = {
  tabs: Tab[];
  active: string;
  onChange: (id: string) => void;
};

export function PageTabs({ tabs, active, onChange }: Props) {
  return (
    <div className="flex flex-wrap gap-1 border-b border-slate-200 pb-3 dark:border-slate-700">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          onClick={() => onChange(tab.id)}
          className={`rounded px-3 py-2 text-sm font-medium focus:outline-none focus:ring-2 focus:ring-teal-700 focus:ring-offset-2 dark:focus:ring-offset-slate-950 ${
            active === tab.id
              ? "bg-slate-900 text-white dark:bg-slate-700"
              : "text-slate-700 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"
          }`}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}
